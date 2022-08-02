// Copyright 2017 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// sample-bar demonstrates a sample i3bar built using barista.
package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image/color"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"barista.run"
	"barista.run/bar"
	"barista.run/base/click"
	"barista.run/base/watchers/netlink"
	"barista.run/colors"
	"barista.run/format"
	"barista.run/group/modal"
	"barista.run/modules/battery"
	"barista.run/modules/clock"
	"barista.run/modules/cputemp"
	"barista.run/modules/diskio"
	"barista.run/modules/diskspace"
	"barista.run/modules/funcs"

	//"barista.run/modules/github"
	"barista.run/modules/media"
	"barista.run/modules/meminfo"
	"barista.run/modules/meta/split"
	"barista.run/modules/netinfo"
	"barista.run/modules/netspeed"
	"barista.run/modules/sysinfo"
	"barista.run/modules/volume"
	"barista.run/modules/volume/alsa"
	"barista.run/modules/wlan"
	"barista.run/oauth"
	"barista.run/outputs"
	"barista.run/pango"
	"barista.run/pango/icons/mdi"
	"barista.run/pango/icons/typicons"

	"github.com/martinohmann/barista-contrib/modules/keyboard"
	"github.com/martinohmann/barista-contrib/modules/keyboard/xkbmap"

	colorful "github.com/lucasb-eyer/go-colorful"
	"github.com/martinlindhe/unit"
	keyring "github.com/zalando/go-keyring"
)

var spacer = pango.Text(" ").XXSmall()
var mainModalController modal.Controller

func truncate(in string, l int) string {
	fromStart := false
	if l < 0 {
		fromStart = true
		l = -l
	}
	inLen := len([]rune(in))
	if inLen <= l {
		return in
	}
	if fromStart {
		return "⋯" + string([]rune(in)[inLen-l+1:])
	}
	return string([]rune(in)[:l-1]) + "⋯"
}

func hms(d time.Duration) (h int, m int, s int) {
	h = int(d.Hours())
	m = int(d.Minutes()) % 60
	s = int(d.Seconds()) % 60
	return
}

func formatMediaTime(d time.Duration) string {
	h, m, s := hms(d)
	if h > 0 {
		return fmt.Sprintf("%d:%02d:%02d", h, m, s)
	}
	return fmt.Sprintf("%d:%02d", m, s)
}

func makeMediaIconAndPosition(m media.Info) *pango.Node {
	iconAndPosition := pango.Icon("mdi-music").Color(colors.Hex("#f70"))
	if m.PlaybackStatus == media.Playing {
		iconAndPosition.Append(spacer,
			pango.Textf("%s/", formatMediaTime(m.Position())))
	}
	if m.PlaybackStatus == media.Paused || m.PlaybackStatus == media.Playing {
		iconAndPosition.Append(spacer,
			pango.Textf("%s", formatMediaTime(m.Length)))
	}
	return iconAndPosition
}

func mediaFormatFunc(m media.Info) bar.Output {
	if m.PlaybackStatus == media.Stopped || m.PlaybackStatus == media.Disconnected {
		return nil
	}
	artist := truncate(m.Artist, 35)
	title := truncate(m.Title, 70-len(artist))
	if len(title) < 35 {
		artist = truncate(m.Artist, 35-len(title))
	}
	var iconAndPosition bar.Output
	if m.PlaybackStatus == media.Playing {
		iconAndPosition = outputs.Repeat(func(time.Time) bar.Output {
			return makeMediaIconAndPosition(m)
		}).Every(time.Second)
	} else {
		iconAndPosition = makeMediaIconAndPosition(m)
	}
	return outputs.Group(iconAndPosition, outputs.Pango(title, " - ", artist))
}

func home(path ...string) string {
	usr, err := user.Current()
	if err != nil {
		panic(err)
	}
	args := append([]string{usr.HomeDir}, path...)
	return filepath.Join(args...)
}

func deviceForMountPath(path string) string {
	mnt, _ := exec.Command("df", "-P", path).Output()
	lines := strings.Split(string(mnt), "\n")
	if len(lines) > 1 {
		devAlias := strings.Split(lines[1], " ")[0]
		dev, _ := exec.Command("realpath", devAlias).Output()
		devStr := strings.TrimSpace(string(dev))
		if devStr != "" {
			return devStr
		}
		return devAlias
	}
	return ""
}

func setupOauthEncryption() error {
	const service = "barista-sample-bar"
	var username string
	if u, err := user.Current(); err == nil {
		username = u.Username
	} else {
		username = fmt.Sprintf("user-%d", os.Getuid())
	}
	var secretBytes []byte
	// IMPORTANT: The oauth tokens used by some modules are very sensitive, so
	// we encrypt them with a random key and store that random key using
	// libsecret (gnome-keyring or equivalent). If no secret provider is
	// available, there is no way to store tokens (since the version of
	// sample-bar used for setup-oauth will have a different key from the one
	// running in i3bar). See also https://github.com/zalando/go-keyring#linux.
	secret, err := keyring.Get(service, username)
	if err == nil {
		secretBytes, err = base64.RawURLEncoding.DecodeString(secret)
	}
	if err != nil {
		secretBytes = make([]byte, 64)
		_, err := rand.Read(secretBytes)
		if err != nil {
			return err
		}
		secret = base64.RawURLEncoding.EncodeToString(secretBytes)
		err = keyring.Set(service, username, secret)
		if err != nil {
			return err
		}
	}
	oauth.SetEncryptionKey(secretBytes)
	return nil
}

func makeIconOutput(key string) *bar.Segment {
	return outputs.Pango(spacer, pango.Icon(key), spacer)
}

var gsuiteOauthConfig = []byte(`{"installed": {
	"client_id":"%%GOOGLE_CLIENT_ID%%",
	"project_id":"i3-barista",
	"auth_uri":"https://accounts.google.com/o/oauth2/auth",
	"token_uri":"https://www.googleapis.com/oauth2/v3/token",
	"auth_provider_x509_cert_url":"https://www.googleapis.com/oauth2/v1/certs",
	"client_secret":"%%GOOGLE_CLIENT_SECRET%%",
	"redirect_uris":["urn:ietf:wg:oauth:2.0:oob","http://localhost"]
}}`)

func threshold(out *bar.Segment, urgent bool, color ...bool) *bar.Segment {
	if urgent {
		return out.Urgent(true)
	}
	colorKeys := []string{"bad", "degraded", "good"}
	for i, c := range colorKeys {
		if len(color) > i && color[i] {
			return out.Color(colors.Scheme(c))
		}
	}
	return out
}

func main() {
	mdi.Load(home(".local/share/fonts/MaterialDesign-Webfont"))
	typicons.Load(home(".local/share/fonts/typicons.font"))

	colors.LoadBarConfig()
	if colors.Scheme("background") == nil {
		colors.Set("background", color.Black)
	}
	if colors.Scheme("statusline") == nil {
		colors.Set("statusline", color.White)
	}
	bg := colors.Scheme("background")
	fg := colors.Scheme("statusline")
	if fg != nil && bg != nil {
		_, _, v := fg.Colorful().Hsv()
		if v < 0.3 {
			v = 0.3
		}
		colors.Set("bad", colorful.Hcl(40, 1.0, v).Clamped())
		colors.Set("degraded", colorful.Hcl(90, 1.0, v).Clamped())
		colors.Set("good", colorful.Hcl(120, 1.0, v).Clamped())
	}

	if err := setupOauthEncryption(); err != nil {
		panic(fmt.Sprintf("Could not setup oauth token encryption: %v", err))
	}

	localdate := clock.Local().
		Output(time.Second, func(now time.Time) bar.Output {
			return outputs.Pango(
				pango.Icon("mdi-calendar-today").Alpha(0.6),
				now.Format("Mon Jan 2"),
			).OnClick(click.RunLeft("gsimplecal"))
		})

	localtime := clock.Local().
		Output(time.Second, func(now time.Time) bar.Output {
			return outputs.Text(now.Format("15:04:05")).
				OnClick(click.Left(func() {
					mainModalController.Toggle("timezones")
				}))
		})

	makeTzClock := func(lbl, tzName string) bar.Module {
		c, err := clock.ZoneByName(tzName)
		if err != nil {
			panic(err)
		}
		return c.Output(time.Minute, func(now time.Time) bar.Output {
			return outputs.Pango(pango.Text(lbl).Smaller(), spacer, now.Format("15:04"))
		})
	}

	battSummary, battDetail := split.New(battery.All().Output(func(i battery.Info) bar.Output {
		if i.Status == battery.Disconnected || i.Status == battery.Unknown {
			return nil
		}
		iconName := "battery"
		if i.Status == battery.Charging {
			iconName += "-charging"
		}
		tenth := i.RemainingPct() / 10
		switch {
		case tenth == 0:
			iconName += "-outline"
		case tenth < 10:
			iconName += fmt.Sprintf("-%d0", tenth)
		}
		mainModalController.SetOutput("battery", makeIconOutput("mdi-"+iconName))
		rem := i.RemainingTime()
		out := outputs.Group()
		// First segment will be used in summary mode.
		out.Append(outputs.Pango(
			pango.Icon("mdi-"+iconName).Alpha(0.6),
			pango.Textf("%d:%02d", int(rem.Hours()), int(rem.Minutes())%60),
		).OnClick(click.Left(func() {
			mainModalController.Toggle("battery")
		})))
		// Others in detail mode.
		out.Append(outputs.Pango(
			pango.Icon("mdi-"+iconName).Alpha(0.6),
			pango.Textf("%d%%", i.RemainingPct()),
			spacer,
			pango.Textf("(%d:%02d)", int(rem.Hours()), int(rem.Minutes())%60),
		).OnClick(click.Left(func() {
			mainModalController.Toggle("battery")
		})))
		out.Append(outputs.Pango(
			pango.Textf("%4.1f/%4.1f", i.EnergyNow, i.EnergyFull),
			pango.Text("Wh").Smaller(),
		))
		out.Append(outputs.Pango(
			pango.Textf("% +6.2f", i.SignedPower()),
			pango.Text("W").Smaller(),
		))
		switch {
		case i.RemainingPct() <= 5:
			out.Urgent(true)
		case i.RemainingPct() <= 15:
			out.Color(colors.Scheme("bad"))
		case i.RemainingPct() <= 25:
			out.Color(colors.Scheme("degraded"))
		}
		return out
	}), 1)

	wifi := wlan.Any().Output(func(i wlan.Info) bar.Output {
		if !i.Connecting() && !i.Connected() {
			return outputs.Pango(pango.Icon("mdi-wifi").Alpha(0.6), "...").
				Color(colors.Scheme("bad"))
		}
		if i.Connecting() {
			return outputs.Pango(pango.Icon("mdi-wifi").Alpha(0.6), "...").
				Color(colors.Scheme("degraded"))
		}
		out := outputs.Group()
		out.Color(colors.Scheme("good"))
		//out.Border(color.RGBA{0, 0, 0xab, 0xff})
		out.Color(color.RGBA{0, 0, 0xab, 0xff})
		// First segment shown in summary mode only.
		// Full name, frequency, bssid in detail mode
		out.Append(outputs.Pango(
			pango.Icon("mdi-wifi").Alpha(0.6),
			pango.Text(i.SSID),
		))
		if i.Frequency.Gigahertz() > 0 {
			out.Append(outputs.Textf("%2.1fGHz", i.Frequency.Gigahertz()))
		}

		if i.AccessPointMAC != "" {
			out.Append(outputs.Pango(
				pango.Icon("mdi-access-point").Alpha(0.8),
				pango.Text(i.AccessPointMAC).Small(),
			))
		}
		return out
	})

	vol := volume.New(alsa.DefaultMixer()).Output(func(v volume.Volume) bar.Output {
		if v.Mute {
			return outputs.
				Pango(pango.Icon("mdi-volume-mute").Alpha(0.8), spacer, "MUT").
				Color(colors.Scheme("degraded"))
		}
		iconName := "low"
		pct := v.Pct()
		if pct > 66 {
			iconName = "high"
		} else if pct > 33 {
			iconName = "medium"
		}
		return outputs.Pango(
			pango.Icon("mdi-volume-"+iconName).Alpha(0.8),
			spacer,
			pango.Textf("%2d%%", pct),
		)
	})

	loadAvg := sysinfo.New().Output(func(s sysinfo.Info) bar.Output {
		out := outputs.Pango(
			pango.Icon("mdi-desktop-tower").Alpha(0.6),
			pango.Textf("%0.2f", s.Loads[0]),
		)
		// Load averages are unusually high for a few minutes after boot.
		if s.Uptime < 10*time.Minute {
			// so don't add colours until 10 minutes after system start.
			return out
		}
		threshold(out,
			s.Loads[0] > 128 || s.Loads[2] > 64,
			s.Loads[0] > 64 || s.Loads[2] > 32,
			s.Loads[0] > 32 || s.Loads[2] > 16,
		)
		out.OnClick(click.Left(func() {
			mainModalController.Toggle("sysinfo")
		}))
		return out
	})

	loadAvgDetail := sysinfo.New().Output(func(s sysinfo.Info) bar.Output {
		return pango.Textf("%0.2f %0.2f", s.Loads[1], s.Loads[2]).Smaller()
	})

	uptime := sysinfo.New().Output(func(s sysinfo.Info) bar.Output {
		u := s.Uptime
		var uptimeOut *pango.Node
		if u.Hours() < 24 {
			uptimeOut = pango.Textf("%d:%02d",
				int(u.Hours()), int(u.Minutes())%60)
		} else {
			uptimeOut = pango.Textf("%dd%02dh",
				int(u.Hours()/24), int(u.Hours())%24)
		}
		return pango.Icon("mdi-trending-up").Alpha(0.6).Concat(uptimeOut)
	})

	freeMem := meminfo.New().Output(func(m meminfo.Info) bar.Output {
		out := outputs.Pango(
			pango.Icon("mdi-memory").Alpha(0.8),
			format.IBytesize(m.Available()),
		)
		freeGigs := m.Available().Gigabytes()
		threshold(out,
			freeGigs < 0.5,
			freeGigs < 1,
			freeGigs < 2,
			freeGigs > 12)
		out.OnClick(click.Left(func() {
			mainModalController.Toggle("sysinfo")
		}))
		return out
	})

	swapMem := meminfo.New().Output(func(m meminfo.Info) bar.Output {
		return outputs.Pango(
			pango.Icon("mdi-swap-horizontal").Alpha(0.8),
			format.IBytesize(m["SwapTotal"]-m["SwapFree"]), spacer,
			pango.Textf("(% 2.0f%%)", (1-m.FreeFrac("Swap"))*100.0).Small(),
		)
	})

	temp := cputemp.New().
		RefreshInterval(2 * time.Second).
		Output(func(temp unit.Temperature) bar.Output {
			out := outputs.Pango(
				pango.Icon("mdi-fan").Alpha(0.6), spacer,
				pango.Textf("%2d℃", int(temp.Celsius())),
			)
			threshold(out,
				temp.Celsius() > 90,
				temp.Celsius() > 70,
				temp.Celsius() > 60,
			)
			return out
		})

	sub := netlink.Any()
	iface := sub.Get().Name
	sub.Unsubscribe()
	netsp := netspeed.New(iface).
		RefreshInterval(2 * time.Second).
		Output(func(s netspeed.Speeds) bar.Output {
			return outputs.Pango(
				pango.Icon("mdi-upload").Alpha(0.5), spacer, pango.Textf("%8s", format.Byterate(s.Tx)),
				pango.Text(" ").Small(),
				pango.Icon("mdi-download").Alpha(0.5), spacer, pango.Textf("%8s", format.Byterate(s.Rx)),
			)
		})

	net := netinfo.New().Output(func(i netinfo.State) bar.Output {
		if !i.Enabled() {
			return nil
		}
		if i.Connecting() || len(i.IPs) < 1 {
			return outputs.Text(i.Name).Color(colors.Scheme("degraded"))
		}
		return outputs.Textf("%s: %v", i.Name, i.IPs[0])
	})

	gpd := netinfo.Interface("gpd0").Output(func(s netinfo.State) bar.Output {
		if len(s.IPs) < 1 {
			return outputs.Text("No network").Color(colors.Scheme("bad"))
		}

		return outputs.Pango(pango.Icon("mdi-security-network").Alpha(0.8), fmt.Sprintf("%s: %v", s.Name, s.IPs[0]))
	})

	formatDiskSpace := func(i diskspace.Info, icon string) bar.Output {
		out := outputs.Pango(
			pango.Icon(icon).Alpha(0.7), spacer, format.IBytesize(i.Available))
		return threshold(out,
			i.Available.Gigabytes() < 1,
			i.AvailFrac() < 0.05,
			i.AvailFrac() < 0.1,
		)
	}

	rootDev := deviceForMountPath("/")
	var homeDiskspace bar.Module
	if deviceForMountPath(home()) != rootDev {
		homeDiskspace = diskspace.New(home()).Output(func(i diskspace.Info) bar.Output {
			return formatDiskSpace(i, "typecn-home-outline")
		})
	}
	rootDiskspace := diskspace.New("/").Output(func(i diskspace.Info) bar.Output {
		return formatDiskSpace(i, "mdi-harddisk")
	})

	mainDiskio := diskio.New(strings.TrimPrefix(rootDev, "/dev/")).
		Output(func(r diskio.IO) bar.Output {
			return pango.Icon("mdi-swap-vertical").
				Concat(spacer).
				ConcatText(format.IByterate(r.Total()))
		})

	mediaSummary, mediaDetail := split.New(media.Auto().Output(mediaFormatFunc), 1)

	kbd := xkbmap.New("us", "no").Output(func(layout keyboard.Layout) bar.Output {
		return outputs.Pango(pango.Icon("mdi-keyboard").Alpha(0.8), strings.ToUpper(layout.Name)).OnClick(func(e bar.Event) {
			switch e.Button {
			case bar.ButtonLeft:
				layout.Next()
			case bar.ButtonRight:
				layout.Previous()
			}
		})
	})

	ghModule := funcs.Every(5*time.Minute, func(s bar.Sink) {
		s.Output(outputs.Text("..."))
		q := fmt.Sprintf(`fragment pr on PullRequest {
  __typename
  updatedAt
  title
  number
  repository {
    nameWithOwner
  }
}

query AssignedSearch {
  reviewRequested: search(
    first: 25
    type: ISSUE
    query: "review-requested:@me state:open archived:false updated:>%s"
  ) {
    nodes {
      ...pr
    }
  }
}
`, time.Now().Add(-3*24*time.Hour).Format("2006-01-02"))
		cmd := exec.Command("gh", "api", "graphql", "-f", "query="+q)
		combined, err := cmd.CombinedOutput()
		if err == nil {
			requests := strings.Count(string(combined), "__typename")
			color := colors.Scheme("good")
			if requests > 0 {
				color = colors.Scheme("degraded")
			}

			s.Output(
				outputs.Pango(pango.Icon("mdi-git").Color(color).AppendTextf("GH:%d", requests)).
					OnClick(click.RunLeft("xdg-open", "https://github.com/pulls/review-requested")))
		} else {
			s.Output(outputs.Textf("ERR:%v", err.Error()))
		}
	})

	bbDomain, _ := os.ReadFile(home(".bitbucket_domain"))
	bbToken, _ := os.ReadFile(home(".bitbucket_token"))

	bbModule := funcs.Every(1*time.Minute, func(s bar.Sink) {
		s.Output(outputs.Text("..."))
		req, err := http.NewRequest("GET", "https://"+string(bbDomain)+"/rest/api/1.0/dashboard/pull-requests?state=OPEN&role=REVIEWER", nil)
		if err != nil {
			s.Output(outputs.Textf("ERR:%v", err.Error()))
			return
		}

		req.Header.Add("Authorization", "Bearer "+string(bbToken))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			s.Output(outputs.Textf("ERR:%v", err.Error()))
			return
		}

		data, err := io.ReadAll(resp.Body)
		if err == nil {
			type Resp struct {
				Values []struct {
					ID          int64 `json:"id"`
					UpdatedDate int64 `json:"updatedDate"`
					Author      struct {
						User struct {
							Name string `json:"name"`
						} `json:"user"`
					} `json:"author"`
					Reviewers []struct {
						User struct {
							Name string `json:"name"`
						} `json:"user"`
						Approved bool `json:"approved"`
					} `json:"reviewers"`
				} `json:"values"`
			}
			var payload Resp
			err := json.Unmarshal(data, &payload)
			if err != nil {
				s.Output(outputs.Textf("ERR:%v", err.Error()))
				return
			}

			color := colors.Scheme("good")
			requests := 0
			cutoff := time.Now().Add(-2 * 24 * time.Hour).UnixMilli()
			for _, req := range payload.Values {
				approved := false
				for _, r := range req.Reviewers {
					if r.User.Name == "a9696" && r.Approved {
						approved = true
						break
					}
				}

				if req.UpdatedDate > cutoff && !approved && req.Author.User.Name != "renovate" {
					requests++
				}
			}

			if requests > 0 {
				color = colors.Scheme("degraded")
			}

			s.Output(
				outputs.Pango(pango.Icon("mdi-git").Color(color).AppendTextf("BB:%d", requests)).
					OnClick(click.RunLeft("xdg-open", "https://"+string(bbDomain)+"/dashboard")))
		} else {
			s.Output(outputs.Textf("ERR:%v", err.Error()))
		}
	})

	mainModal := modal.New()
	sysMode := mainModal.Mode("sysinfo").
		SetOutput(makeIconOutput("mdi-chart-areaspline")).
		Add(loadAvg).
		Detail(loadAvgDetail, uptime).
		Add(freeMem).
		Detail(swapMem, temp)
	if homeDiskspace != nil {
		sysMode.Detail(homeDiskspace)
	}
	sysMode.Detail(rootDiskspace, mainDiskio)
	mainModal.Mode("media").
		SetOutput(makeIconOutput("mdi-music-box")).
		Add(mediaSummary).
		Detail(mediaDetail)
	mainModal.Mode("battery").
		// Filled in by the battery module if one is available.
		SetOutput(nil).
		Summary(battSummary).
		Detail(battDetail)
	mainModal.Mode("timezones").
		SetOutput(makeIconOutput("mdi-map")).
		Detail(makeTzClock("Seattle", "America/Los_Angeles")).
		Detail(makeTzClock("New York", "America/New_York")).
		Detail(makeTzClock("UTC", "Etc/UTC")).
		Detail(makeTzClock("Oslo", "Europe/Oslo")).
		Add(localdate)

	var mm bar.Module
	mm, mainModalController = mainModal.Build()
	modules := []bar.Module{
		mm, vol, wifi, net, netsp, gpd, kbd, ghModule,
	}
	if bbDomain != nil {
		modules = append(modules, bbModule)
	}
	modules = append(modules, localtime)
	panic(barista.Run(modules...))
}
