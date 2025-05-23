//go:build !scanner

package detector

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"golang.org/x/xerrors"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/constant"
	"github.com/future-architect/vuls/contrib/owasp-dependency-check/parser"
	"github.com/future-architect/vuls/cwe"
	"github.com/future-architect/vuls/detector/vuls2"
	"github.com/future-architect/vuls/gost"
	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/oval"
	"github.com/future-architect/vuls/reporter"
	"github.com/future-architect/vuls/util"
	cvemodels "github.com/vulsio/go-cve-dictionary/models"
)

// Cpe :
type Cpe struct {
	CpeURI string
	UseJVN bool
}

// Detect vulns and fill CVE detailed information
func Detect(rs []models.ScanResult, dir string) ([]models.ScanResult, error) {

	// Use the same reportedAt for all rs
	reportedAt := time.Now()
	for i, r := range rs {
		if !config.Conf.RefreshCve && !needToRefreshCve(r) {
			logging.Log.Info("No need to refresh")
			continue
		}

		if !reuseScannedCves(&r) {
			r.ScannedCves = models.VulnInfos{}
		}

		if err := DetectLibsCves(&r, config.Conf.TrivyOpts, config.Conf.LogOpts, config.Conf.NoProgress); err != nil {
			return nil, xerrors.Errorf("Failed to fill with Library dependency: %w", err)
		}

		if err := DetectPkgCves(&r, config.Conf.OvalDict, config.Conf.Gost, config.Conf.Vuls2, config.Conf.LogOpts, config.Conf.NoProgress); err != nil {
			return nil, xerrors.Errorf("Failed to detect Pkg CVE: %w", err)
		}

		cpeURIs, owaspDCXMLPath := []string{}, ""
		cpes := []Cpe{}
		if len(r.Container.ContainerID) == 0 {
			cpeURIs = config.Conf.Servers[r.ServerName].CpeNames
			owaspDCXMLPath = config.Conf.Servers[r.ServerName].OwaspDCXMLPath
		} else {
			if s, ok := config.Conf.Servers[r.ServerName]; ok {
				if con, ok := s.Containers[r.Container.Name]; ok {
					cpeURIs = con.Cpes
					owaspDCXMLPath = con.OwaspDCXMLPath
				}
			}
		}
		if owaspDCXMLPath != "" {
			cpes, err := parser.Parse(owaspDCXMLPath)
			if err != nil {
				return nil, xerrors.Errorf("Failed to read OWASP Dependency Check XML on %s, `%s`, err: %w",
					r.ServerInfo(), owaspDCXMLPath, err)
			}
			cpeURIs = append(cpeURIs, cpes...)
		}
		for _, uri := range cpeURIs {
			cpes = append(cpes, Cpe{
				CpeURI: uri,
				UseJVN: true,
			})
		}

		if slices.Contains([]string{constant.MacOSX, constant.MacOSXServer, constant.MacOS, constant.MacOSServer}, r.Family) {
			var targets []string
			if r.Release != "" {
				switch r.Family {
				case constant.MacOSX:
					targets = append(targets, "mac_os_x")
				case constant.MacOSXServer:
					targets = append(targets, "mac_os_x_server")
				case constant.MacOS:
					targets = append(targets, "macos", "mac_os")
				case constant.MacOSServer:
					targets = append(targets, "macos_server", "mac_os_server")
				}
				for _, t := range targets {
					cpes = append(cpes, Cpe{
						CpeURI: fmt.Sprintf("cpe:/o:apple:%s:%s", t, r.Release),
						UseJVN: false,
					})
				}
			}
			for _, p := range r.Packages {
				if p.Version == "" {
					continue
				}
				switch p.Repository {
				case "com.apple.Safari":
					for _, t := range targets {
						cpes = append(cpes, Cpe{
							CpeURI: fmt.Sprintf("cpe:/a:apple:safari:%s::~~~%s~~", p.Version, t),
							UseJVN: false,
						})
					}
				case "com.apple.Music":
					for _, t := range targets {
						cpes = append(cpes,
							Cpe{
								CpeURI: fmt.Sprintf("cpe:/a:apple:music:%s::~~~%s~~", p.Version, t),
								UseJVN: false,
							},
							Cpe{
								CpeURI: fmt.Sprintf("cpe:/a:apple:apple_music:%s::~~~%s~~", p.Version, t),
								UseJVN: false,
							},
						)
					}
				case "com.apple.mail":
					for _, t := range targets {
						cpes = append(cpes, Cpe{
							CpeURI: fmt.Sprintf("cpe:/a:apple:mail:%s::~~~%s~~", p.Version, t),
							UseJVN: false,
						})
					}
				case "com.apple.Terminal":
					for _, t := range targets {
						cpes = append(cpes, Cpe{
							CpeURI: fmt.Sprintf("cpe:/a:apple:terminal:%s::~~~%s~~", p.Version, t),
							UseJVN: false,
						})
					}
				case "com.apple.shortcuts":
					for _, t := range targets {
						cpes = append(cpes, Cpe{
							CpeURI: fmt.Sprintf("cpe:/a:apple:shortcuts:%s::~~~%s~~", p.Version, t),
							UseJVN: false,
						})
					}
				case "com.apple.iCal":
					for _, t := range targets {
						cpes = append(cpes, Cpe{
							CpeURI: fmt.Sprintf("cpe:/a:apple:ical:%s::~~~%s~~", p.Version, t),
							UseJVN: false,
						})
					}
				case "com.apple.iWork.Keynote":
					for _, t := range targets {
						cpes = append(cpes, Cpe{
							CpeURI: fmt.Sprintf("cpe:/a:apple:keynote:%s::~~~%s~~", p.Version, t),
							UseJVN: false,
						})
					}
				case "com.apple.iWork.Numbers":
					for _, t := range targets {
						cpes = append(cpes, Cpe{
							CpeURI: fmt.Sprintf("cpe:/a:apple:numbers:%s::~~~%s~~", p.Version, t),
							UseJVN: false,
						})
					}
				case "com.apple.iWork.Pages":
					for _, t := range targets {
						cpes = append(cpes, Cpe{
							CpeURI: fmt.Sprintf("cpe:/a:apple:pages:%s::~~~%s~~", p.Version, t),
							UseJVN: false,
						})
					}
				case "com.apple.dt.Xcode":
					for _, t := range targets {
						cpes = append(cpes, Cpe{
							CpeURI: fmt.Sprintf("cpe:/a:apple:xcode:%s::~~~%s~~", p.Version, t),
							UseJVN: false,
						})
					}
				}
			}
		}

		if err := DetectCpeURIsCves(&r, cpes, config.Conf.CveDict, config.Conf.LogOpts); err != nil {
			return nil, xerrors.Errorf("Failed to detect CVE of `%s`: %w", cpeURIs, err)
		}

		repos := config.Conf.Servers[r.ServerName].GitHubRepos
		if err := DetectGitHubCves(&r, repos); err != nil {
			return nil, xerrors.Errorf("Failed to detect GitHub Cves: %w", err)
		}

		if err := DetectWordPressCves(&r, config.Conf.WpScan); err != nil {
			return nil, xerrors.Errorf("Failed to detect WordPress Cves: %w", err)
		}

		if err := gost.FillCVEsWithRedHat(&r, config.Conf.Gost, config.Conf.LogOpts); err != nil {
			return nil, xerrors.Errorf("Failed to fill with gost: %w", err)
		}

		if err := FillCvesWithGoCVEDictionary(&r, config.Conf.CveDict, config.Conf.LogOpts); err != nil {
			return nil, xerrors.Errorf("Failed to fill with CVE: %w", err)
		}

		nExploitCve, err := FillWithExploit(&r, config.Conf.Exploit, config.Conf.LogOpts)
		if err != nil {
			return nil, xerrors.Errorf("Failed to fill with exploit: %w", err)
		}
		logging.Log.Infof("%s: %d PoC are detected", r.FormatServerName(), nExploitCve)

		nMetasploitCve, err := FillWithMetasploit(&r, config.Conf.Metasploit, config.Conf.LogOpts)
		if err != nil {
			return nil, xerrors.Errorf("Failed to fill with metasploit: %w", err)
		}
		logging.Log.Infof("%s: %d exploits are detected", r.FormatServerName(), nMetasploitCve)

		if err := FillWithKEVuln(&r, config.Conf.KEVuln, config.Conf.LogOpts); err != nil {
			return nil, xerrors.Errorf("Failed to fill with Known Exploited Vulnerabilities: %w", err)
		}

		if err := FillWithCTI(&r, config.Conf.Cti, config.Conf.LogOpts); err != nil {
			return nil, xerrors.Errorf("Failed to fill with Cyber Threat Intelligences: %w", err)
		}

		FillCweDict(&r)

		r.ReportedBy, _ = os.Hostname()
		r.Lang = config.Conf.Lang
		r.ReportedAt = reportedAt
		r.ReportedVersion = config.Version
		r.ReportedRevision = config.Revision
		r.Config.Report = config.Conf
		r.Config.Report.Servers = map[string]config.ServerInfo{
			r.ServerName: config.Conf.Servers[r.ServerName],
		}
		rs[i] = r
	}

	// Overwrite the json file every time to clear the fields specified in config.IgnoredJSONKeys
	for _, r := range rs {
		if s, ok := config.Conf.Servers[r.ServerName]; ok {
			r = r.ClearFields(s.IgnoredJSONKeys)
		}
		//TODO don't call here
		if err := reporter.OverwriteJSONFile(dir, r); err != nil {
			return nil, xerrors.Errorf("Failed to write JSON: %w", err)
		}
	}

	if config.Conf.DiffPlus || config.Conf.DiffMinus {
		prevs, err := loadPrevious(rs, config.Conf.ResultsDir)
		if err != nil {
			return nil, xerrors.Errorf("Failed to load previous results. err: %w", err)
		}
		rs = diff(rs, prevs, config.Conf.DiffPlus, config.Conf.DiffMinus)
	}

	for i, r := range rs {
		nFiltered := 0
		logging.Log.Infof("%s: total %d CVEs detected", r.FormatServerName(), len(r.ScannedCves))

		if 0 < config.Conf.CvssScoreOver {
			r.ScannedCves, nFiltered = r.ScannedCves.FilterByCvssOver(config.Conf.CvssScoreOver)
			logging.Log.Infof("%s: %d CVEs filtered by --cvss-over=%g", r.FormatServerName(), nFiltered, config.Conf.CvssScoreOver)
		}

		if config.Conf.IgnoreUnfixed {
			r.ScannedCves, nFiltered = r.ScannedCves.FilterUnfixed(config.Conf.IgnoreUnfixed)
			logging.Log.Infof("%s: %d CVEs filtered by --ignore-unfixed", r.FormatServerName(), nFiltered)
		}

		if 0 < config.Conf.ConfidenceScoreOver {
			r.ScannedCves, nFiltered = r.ScannedCves.FilterByConfidenceOver(config.Conf.ConfidenceScoreOver)
			logging.Log.Infof("%s: %d CVEs filtered by --confidence-over=%d", r.FormatServerName(), nFiltered, config.Conf.ConfidenceScoreOver)
		}

		// IgnoreCves
		ignoreCves := []string{}
		if r.Container.Name == "" {
			ignoreCves = config.Conf.Servers[r.ServerName].IgnoreCves
		} else if con, ok := config.Conf.Servers[r.ServerName].Containers[r.Container.Name]; ok {
			ignoreCves = con.IgnoreCves
		}
		if 0 < len(ignoreCves) {
			r.ScannedCves, nFiltered = r.ScannedCves.FilterIgnoreCves(ignoreCves)
			logging.Log.Infof("%s: %d CVEs filtered by ignoreCves=%s", r.FormatServerName(), nFiltered, ignoreCves)
		}

		// ignorePkgs
		ignorePkgsRegexps := []string{}
		if r.Container.Name == "" {
			ignorePkgsRegexps = config.Conf.Servers[r.ServerName].IgnorePkgsRegexp
		} else if s, ok := config.Conf.Servers[r.ServerName].Containers[r.Container.Name]; ok {
			ignorePkgsRegexps = s.IgnorePkgsRegexp
		}
		if 0 < len(ignorePkgsRegexps) {
			r.ScannedCves, nFiltered = r.ScannedCves.FilterIgnorePkgs(ignorePkgsRegexps)
			logging.Log.Infof("%s: %d CVEs filtered by ignorePkgsRegexp=%s", r.FormatServerName(), nFiltered, ignorePkgsRegexps)
		}

		// IgnoreUnscored
		if config.Conf.IgnoreUnscoredCves {
			r.ScannedCves, nFiltered = r.ScannedCves.FindScoredVulns()
			logging.Log.Infof("%s: %d CVEs filtered by --ignore-unscored-cves", r.FormatServerName(), nFiltered)
		}

		r.FilterInactiveWordPressLibs(config.Conf.WpScan.DetectInactive)
		rs[i] = r
	}
	return rs, nil
}

// DetectPkgCves detects OS pkg cves
// pass 2 configs
func DetectPkgCves(r *models.ScanResult, ovalCnf config.GovalDictConf, gostCnf config.GostConf, vuls2Conf config.Vuls2Conf, logOpts logging.LogOpts, noProgress bool) error {
	// Pkg Scan
	if isPkgCvesDetactable(r) {
		// OVAL, gost(Debian Security Tracker) does not support Package for Raspbian, so skip it.
		if r.Family == constant.Raspbian {
			r = r.RemoveRaspbianPackFromResult()
		}

		// Vuls2
		if err := vuls2.Detect(r, vuls2Conf, noProgress); err != nil {
			return xerrors.Errorf("Failed to detect CVE with Vuls2: %w", err)
		}

		// OVAL
		if err := detectPkgsCvesWithOval(ovalCnf, r, logOpts); err != nil {
			return xerrors.Errorf("Failed to detect CVE with OVAL: %w", err)
		}

		// gost
		if err := detectPkgsCvesWithGost(gostCnf, r, logOpts); err != nil {
			return xerrors.Errorf("Failed to detect CVE with gost: %w", err)
		}
	}

	for i, v := range r.ScannedCves {
		for j, p := range v.AffectedPackages {
			if p.NotFixedYet && p.FixState == "" {
				p.FixState = "Not fixed yet"
				r.ScannedCves[i].AffectedPackages[j] = p
			}
		}
	}

	// To keep backward compatibility
	// Newer versions use ListenPortStats,
	// but older versions of Vuls are set to ListenPorts.
	// Set ListenPorts to ListenPortStats to allow newer Vuls to report old results.
	for i, pkg := range r.Packages {
		for j, proc := range pkg.AffectedProcs {
			for _, ipPort := range proc.ListenPorts {
				ps, err := models.NewPortStat(ipPort)
				if err != nil {
					logging.Log.Warnf("Failed to parse ip:port: %s, err:%+v", ipPort, err)
					continue
				}
				r.Packages[i].AffectedProcs[j].ListenPortStats = append(
					r.Packages[i].AffectedProcs[j].ListenPortStats, *ps)
			}
		}
	}

	return nil
}

// isPkgCvesDetactable checks whether CVEs is detactable with gost and oval from the result
func isPkgCvesDetactable(r *models.ScanResult) bool {
	switch r.Family {
	case constant.FreeBSD, constant.MacOSX, constant.MacOSXServer, constant.MacOS, constant.MacOSServer, constant.ServerTypePseudo:
		logging.Log.Infof("%s type. Skip OVAL and gost detection", r.Family)
		return false
	case constant.Windows:
		return true
	default:
		if r.ScannedVia == "trivy" {
			logging.Log.Infof("r.ScannedVia is trivy. Skip OVAL and gost detection")
			return false
		}

		if r.Release == "" {
			logging.Log.Infof("r.Release is empty. Skip OVAL and gost detection")
			return false
		}

		if len(r.Packages)+len(r.SrcPackages) == 0 {
			logging.Log.Infof("Number of packages is 0. Skip OVAL and gost detection")
			return false
		}
		return true
	}
}

// DetectGitHubCves fetches CVEs from GitHub Security Alerts
func DetectGitHubCves(r *models.ScanResult, githubConfs map[string]config.GitHubConf) error {
	if len(githubConfs) == 0 {
		return nil
	}

	r.GitHubManifests = models.DependencyGraphManifests{}
	for ownerRepo, setting := range githubConfs {
		ss := strings.Split(ownerRepo, "/")
		if len(ss) != 2 {
			return xerrors.Errorf("Failed to parse GitHub owner/repo: %s", ownerRepo)
		}
		owner, repo := ss[0], ss[1]
		n, err := DetectGitHubSecurityAlerts(r, owner, repo, setting.Token, setting.IgnoreGitHubDismissed)
		if err != nil {
			return xerrors.Errorf("Failed to access GitHub Security Alerts: %w", err)
		}
		logging.Log.Infof("%s: %d CVEs detected with GHSA %s/%s",
			r.FormatServerName(), n, owner, repo)

		if err = DetectGitHubDependencyGraph(r, owner, repo, setting.Token); err != nil {
			return xerrors.Errorf("Failed to access GitHub Dependency graph: %w", err)
		}
	}
	return nil
}

// DetectWordPressCves detects CVEs of WordPress
func DetectWordPressCves(r *models.ScanResult, wpCnf config.WpScanConf) error {
	if len(r.WordPressPackages) == 0 {
		return nil
	}
	logging.Log.Infof("%s: Detect WordPress CVE. Number of pkgs: %d ", r.ServerInfo(), len(r.WordPressPackages))
	n, err := detectWordPressCves(r, wpCnf)
	if err != nil {
		return xerrors.Errorf("Failed to detect WordPress CVE: %w", err)
	}
	logging.Log.Infof("%s: found %d WordPress CVEs", r.FormatServerName(), n)
	return nil
}

// FillCvesWithGoCVEDictionary fills CVE detail with NVD, JVN, Fortinet, MITRE
func FillCvesWithGoCVEDictionary(r *models.ScanResult, cnf config.GoCveDictConf, logOpts logging.LogOpts) (err error) {
	cveIDs := []string{}
	for _, v := range r.ScannedCves {
		cveIDs = append(cveIDs, v.CveID)
	}

	client, err := newGoCveDictClient(&cnf, logOpts)
	if err != nil {
		return xerrors.Errorf("Failed to newGoCveDictClient. err: %w", err)
	}
	defer func() {
		if err := client.closeDB(); err != nil {
			logging.Log.Errorf("Failed to close DB. err: %+v", err)
		}
	}()

	ds, err := client.fetchCveDetails(cveIDs)
	if err != nil {
		return xerrors.Errorf("Failed to fetchCveDetails. err: %w", err)
	}

	for _, d := range ds {
		nvds, exploits, mitigations := models.ConvertNvdToModel(d.CveID, d.Nvds)
		jvns := models.ConvertJvnToModel(d.CveID, d.Jvns)
		fortinets := models.ConvertFortinetToModel(d.CveID, d.Fortinets)
		mitres := models.ConvertMitreToModel(d.CveID, d.Mitres)

		alerts := fillCertAlerts(&d)
		for cveID, vinfo := range r.ScannedCves {
			if vinfo.CveID == d.CveID {
				if vinfo.CveContents == nil {
					vinfo.CveContents = models.CveContents{}
				}
				for _, con := range nvds {
					if !con.Empty() {
						vinfo.CveContents[con.Type] = append(vinfo.CveContents[con.Type], con)
					}
				}
				for _, con := range append(jvns, fortinets...) {
					if !con.Empty() {
						if !slices.ContainsFunc(vinfo.CveContents[con.Type], func(e models.CveContent) bool {
							return con.SourceLink == e.SourceLink
						}) {
							vinfo.CveContents[con.Type] = append(vinfo.CveContents[con.Type], con)
						}
					}
				}
				for _, con := range mitres {
					vinfo.CveContents[con.Type] = append(vinfo.CveContents[con.Type], con)
				}
				vinfo.AlertDict = alerts
				vinfo.Exploits = append(vinfo.Exploits, exploits...)
				vinfo.Mitigations = append(vinfo.Mitigations, mitigations...)
				r.ScannedCves[cveID] = vinfo
				break
			}
		}
	}
	return nil
}

func fillCertAlerts(cvedetail *cvemodels.CveDetail) (dict models.AlertDict) {
	for _, nvd := range cvedetail.Nvds {
		for _, cert := range nvd.Certs {
			dict.USCERT = append(dict.USCERT, models.Alert{
				URL:   cert.Link,
				Title: cert.Title,
				Team:  "uscert",
			})
		}
	}

	for _, jvn := range cvedetail.Jvns {
		for _, cert := range jvn.Certs {
			dict.JPCERT = append(dict.JPCERT, models.Alert{
				URL:   cert.Link,
				Title: cert.Title,
				Team:  "jpcert",
			})
		}
	}

	return dict
}

// detectPkgsCvesWithOval fetches OVAL database
func detectPkgsCvesWithOval(cnf config.GovalDictConf, r *models.ScanResult, logOpts logging.LogOpts) error {
	client, err := oval.NewOVALClient(r.Family, cnf, logOpts)
	if err != nil {
		return err
	}
	defer func() {
		if err := client.CloseDB(); err != nil {
			logging.Log.Errorf("Failed to close the OVAL DB. err: %+v", err)
		}
	}()

	switch r.Family {
	case constant.Debian, constant.Raspbian, constant.Ubuntu:
		logging.Log.Infof("Skip OVAL and Scan with gost alone.")
		logging.Log.Infof("%s: %d CVEs are detected with OVAL", r.FormatServerName(), 0)
		return nil
	case constant.RedHat, constant.CentOS, constant.Alma, constant.Rocky:
		logging.Log.Debugf("Skip OVAL and Scan by Vuls2")
		return nil
	case constant.Windows, constant.MacOSX, constant.MacOSXServer, constant.MacOS, constant.MacOSServer, constant.FreeBSD, constant.ServerTypePseudo:
		return nil
	default:
		logging.Log.Debugf("Check if oval fetched: %s %s", r.Family, r.Release)
		ok, err := client.CheckIfOvalFetched(r.Family, r.Release)
		if err != nil {
			return err
		}
		if !ok {
			return xerrors.Errorf("OVAL entries of %s %s are not found. Fetch OVAL before reporting. For details, see `https://github.com/vulsio/goval-dictionary#usage`", r.Family, r.Release)
		}
	}

	logging.Log.Debugf("Check if oval fresh: %s %s", r.Family, r.Release)
	_, err = client.CheckIfOvalFresh(r.Family, r.Release)
	if err != nil {
		return err
	}

	logging.Log.Debugf("Fill with oval: %s %s", r.Family, r.Release)
	nCVEs, err := client.FillWithOval(r)
	if err != nil {
		return err
	}

	logging.Log.Infof("%s: %d CVEs are detected with OVAL", r.FormatServerName(), nCVEs)
	return nil
}

func detectPkgsCvesWithGost(cnf config.GostConf, r *models.ScanResult, logOpts logging.LogOpts) error {
	client, err := gost.NewGostClient(cnf, r.Family, logOpts)
	if err != nil {
		return xerrors.Errorf("Failed to new a gost client: %w", err)
	}
	defer func() {
		if err := client.CloseDB(); err != nil {
			logging.Log.Errorf("Failed to close the gost DB. err: %+v", err)
		}
	}()

	nCVEs, err := client.DetectCVEs(r, true)
	if err != nil {
		switch r.Family {
		case constant.Debian, constant.Raspbian, constant.Ubuntu, constant.Windows:
			return xerrors.Errorf("Failed to detect CVEs with gost: %w", err)
		default:
			return xerrors.Errorf("Failed to detect unfixed CVEs with gost: %w", err)
		}
	}

	switch r.Family {
	case constant.Debian, constant.Raspbian, constant.Ubuntu, constant.Windows:
		logging.Log.Infof("%s: %d CVEs are detected with gost", r.FormatServerName(), nCVEs)
	default:
		logging.Log.Infof("%s: %d unfixed CVEs are detected with gost", r.FormatServerName(), nCVEs)
	}

	return nil
}

// DetectCpeURIsCves detects CVEs of given CPE-URIs
func DetectCpeURIsCves(r *models.ScanResult, cpes []Cpe, cnf config.GoCveDictConf, logOpts logging.LogOpts) error {
	client, err := newGoCveDictClient(&cnf, logOpts)
	if err != nil {
		return xerrors.Errorf("Failed to newGoCveDictClient. err: %w", err)
	}
	defer func() {
		if err := client.closeDB(); err != nil {
			logging.Log.Errorf("Failed to close DB. err: %+v", err)
		}
	}()

	nCVEs := 0
	for _, cpe := range cpes {
		details, err := client.detectCveByCpeURI(cpe.CpeURI, cpe.UseJVN)
		if err != nil {
			return xerrors.Errorf("Failed to detectCveByCpeURI. err: %w", err)
		}

		for _, detail := range details {
			advisories := []models.DistroAdvisory{}
			if detail.HasFortinet() {
				for _, fortinet := range detail.Fortinets {
					advisories = append(advisories, models.DistroAdvisory{
						AdvisoryID: fortinet.AdvisoryID,
					})
				}
			}
			if !detail.HasNvd() && detail.HasJvn() {
				for _, jvn := range detail.Jvns {
					advisories = append(advisories, models.DistroAdvisory{
						AdvisoryID: jvn.JvnID,
					})
				}
			}
			maxConfidence := getMaxConfidence(detail)

			if val, ok := r.ScannedCves[detail.CveID]; ok {
				val.CpeURIs = util.AppendIfMissing(val.CpeURIs, cpe.CpeURI)
				val.Confidences.AppendIfMissing(maxConfidence)
				for _, adv := range advisories {
					val.DistroAdvisories.AppendIfMissing(&adv)
				}
				r.ScannedCves[detail.CveID] = val
			} else {
				v := models.VulnInfo{
					CveID:            detail.CveID,
					CpeURIs:          []string{cpe.CpeURI},
					Confidences:      models.Confidences{maxConfidence},
					DistroAdvisories: advisories,
				}
				r.ScannedCves[detail.CveID] = v
				nCVEs++
			}
		}
	}
	logging.Log.Infof("%s: %d CVEs are detected with CPE", r.FormatServerName(), nCVEs)
	return nil
}

func getMaxConfidence(detail cvemodels.CveDetail) (maxConfidence models.Confidence) {
	if detail.HasFortinet() {
		for _, fortinet := range detail.Fortinets {
			confidence := models.Confidence{}
			switch fortinet.DetectionMethod {
			case cvemodels.FortinetExactVersionMatch:
				confidence = models.FortinetExactVersionMatch
			case cvemodels.FortinetRoughVersionMatch:
				confidence = models.FortinetRoughVersionMatch
			case cvemodels.FortinetVendorProductMatch:
				confidence = models.FortinetVendorProductMatch
			}
			if maxConfidence.Score < confidence.Score {
				maxConfidence = confidence
			}
		}
		return maxConfidence
	}

	if detail.HasNvd() {
		for _, nvd := range detail.Nvds {
			confidence := models.Confidence{}
			switch nvd.DetectionMethod {
			case cvemodels.NvdExactVersionMatch:
				confidence = models.NvdExactVersionMatch
			case cvemodels.NvdRoughVersionMatch:
				confidence = models.NvdRoughVersionMatch
			case cvemodels.NvdVendorProductMatch:
				confidence = models.NvdVendorProductMatch
			}
			if maxConfidence.Score < confidence.Score {
				maxConfidence = confidence
			}
		}
		return maxConfidence
	}

	if detail.HasJvn() {
		return models.JvnVendorProductMatch
	}

	return maxConfidence
}

// FillCweDict fills CWE
func FillCweDict(r *models.ScanResult) {
	uniqCweIDMap := map[string]bool{}
	for _, vinfo := range r.ScannedCves {
		for _, conts := range vinfo.CveContents {
			for _, cont := range conts {
				for _, id := range cont.CweIDs {
					if strings.HasPrefix(id, "CWE-") {
						id = strings.TrimPrefix(id, "CWE-")
						uniqCweIDMap[id] = true
					}
				}
			}
		}
	}

	dict := map[string]models.CweDictEntry{}
	for id := range uniqCweIDMap {
		entry := models.CweDictEntry{
			OwaspTopTens:       map[string]string{},
			CweTopTwentyfives:  map[string]string{},
			SansTopTwentyfives: map[string]string{},
		}
		if e, ok := cwe.CweDictEn[id]; ok {
			fillCweRank(&entry, id)
			entry.En = &e
		} else {
			logging.Log.Debugf("CWE-ID %s is not found in English CWE Dict", id)
			entry.En = &cwe.Cwe{CweID: id}
		}

		if r.Lang == "ja" {
			if e, ok := cwe.CweDictJa[id]; ok {
				fillCweRank(&entry, id)
				entry.Ja = &e
			} else {
				logging.Log.Debugf("CWE-ID %s is not found in Japanese CWE Dict", id)
				entry.Ja = &cwe.Cwe{CweID: id}
			}
		}

		dict[id] = entry
	}
	r.CweDict = dict
}

func fillCweRank(entry *models.CweDictEntry, id string) {
	for year, ranks := range cwe.OwaspTopTens {
		if rank, ok := ranks[id]; ok {
			entry.OwaspTopTens[year] = rank
		}
	}
	for year, ranks := range cwe.CweTopTwentyfives {
		if rank, ok := ranks[id]; ok {
			entry.CweTopTwentyfives[year] = rank
		}
	}
	for year, ranks := range cwe.SansTopTwentyfives {
		if rank, ok := ranks[id]; ok {
			entry.SansTopTwentyfives[year] = rank
		}
	}
}
