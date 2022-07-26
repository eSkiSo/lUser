package main

import (
	"fmt"
	"log"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/ilyakaznacheev/cleanenv"
)

const (
	Version     = 0.3
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorCyan   = "\033[36m"
	italicStart = "\033[3m"
	boldStart   = "\033[1m"
	styleReset  = "\033[0m"
)

type Configs struct {
	BindUsername     string `yaml:"bindusername" env:"BindUsername" env-default:"cn=admin,ou=sysadmins,dc=test,dc=com"`
	BindPassword     string `yaml:"bindpassword" env:"BindPassword" env-default:"secret_password"`
	FQDN             string `yaml:"server" env:"FQDN" env-default:""`
	Port             int    `yaml:"port" env:"Port" env-default:"389"`
	BaseDN           string `yaml:"basedn" env:"BaseDN" env-default:"cn=users,dc=test,dc=com"`
	MaxPwdAge        int    `yaml:"maxpwdage" env:"MaxPwdAge" env-default:"30"`
	Alt_BindUsername string `yaml:"alt_bindusername" env:"Alt_BindUsername" env-default:"cn=admin,ou=sysadmins,dc=test,dc=com"`
	Alt_BindPassword string `yaml:"alt_bindpassword" env:"Alt_BindPassword" env-default:"secret_password"`
	Alt_FQDN         string `yaml:"alt_server" env:"Alt_FQDN" env-default:""`
	Alt_Port         int    `yaml:"alt_port" env:"Alt_Port" env-default:"389"`
	Alt_BaseDN       string `yaml:"alt_basedn" env:"Alt_BaseDN" env-default:"ou=users,ou=guests,dc=test,dc=com"`
	Alt_MaxPwdAge    int    `yaml:"alt_maxpwdage" env:"Alt_MaxPwdAge" env-default:"30"`
}

func printHelp() {
	fmt.Println(colorCyan + boldStart + "lUser LDAP Cli")
	fmt.Println("> luser [optional argument] <user|number|email> <optional search if -gsl or -gs>\n ")
	fmt.Println(colorBlue + "Search User")
	fmt.Println(colorYellow + "> luser <user|number|email> \n ")
	fmt.Println(colorBlue + "Search User with Groups")
	fmt.Println(colorYellow + "> luser -g <user|number|email> " + colorCyan + italicStart + " Separated by |" + styleReset)
	fmt.Println(colorYellow + "> luser -gl <user|number|email> " + colorCyan + italicStart + " Separated by new line \n " + styleReset)
	fmt.Println(colorBlue + "Search User with search/filter of group")
	fmt.Println(colorYellow + "> luser -gs <user|number|email> <text to search> " + colorCyan + italicStart + " Separated by |" + styleReset)
	fmt.Println(colorYellow + "> luser -gsl <user|number|email> <text to search> " + colorCyan + italicStart + " Separated by new line \n " + styleReset)
	fmt.Println(colorBlue + "Search Groups / List Members")
	fmt.Println(colorYellow + "> luser -G <group>")
}

func testPrint() {
	isBlocked := colorGreen + "NO ✅"
	estadoConta := colorGreen + "OK ✅"
	corTempo := colorGreen

	fmt.Printf(colorBlue+"User: "+colorYellow+boldStart+"%s"+styleReset+" \n", "guest")
	fmt.Printf(colorBlue+"Name: "+colorYellow+boldStart+"%s"+styleReset+" \n", "Guest 1")
	fmt.Printf(colorBlue+"Email: "+colorYellow+boldStart+"%s"+styleReset+" \n", "guest@domain.com")
	fmt.Printf(colorBlue+"Numbers: "+colorYellow+boldStart+"%s / %s\n"+styleReset, "1000", "1001")
	fmt.Printf(colorBlue+"Blocked: "+colorYellow+boldStart+"%s\n"+styleReset, isBlocked)
	fmt.Printf(colorBlue+"Status: "+colorYellow+boldStart+"%s\n"+styleReset, estadoConta)
	fmt.Printf(colorBlue+"Password Changed in: "+boldStart+colorYellow+" %s\n"+styleReset, "2022-07-26 23:50:00")
	fmt.Printf(colorBlue+"Password Expirest in: "+boldStart+corTempo+" %d days\n"+styleReset, 30)
	fmt.Printf(colorBlue+"Wrong Passwords: "+boldStart+colorYellow+" %s\n"+styleReset, "0")
	fmt.Printf(colorBlue+"Script: "+boldStart+colorYellow+" %s\n"+styleReset, "")
}

func main() {

	testPrint()
	os.Exit(0)

	if len(os.Args) < 2 {
		fmt.Print(colorRed + boldStart + "You must supply a search parameter (user or group name if -G)" + styleReset + "\n")
		printHelp()
		os.Exit(0)
	}

	searchText := os.Args[1]
	showGroups := false
	showGroupsOptions := "p"
	searchGroup := false

	if searchText == "-h" || searchText == "-help" {
		printHelp()
		os.Exit(0)
	}

	if searchText == "-v" || searchText == "-version" {
		fmt.Printf(colorCyan+boldStart+"lUser LDAP Cli v %v \n"+styleReset, Version)
		os.Exit(0)
	}

	if len(os.Args) > 2 {
		searchText = os.Args[2]
		if os.Args[1] == "-g" {
			showGroups = true
		}
		if os.Args[1] == "-gl" {
			showGroups = true
			showGroupsOptions = "l"
		}
		if os.Args[1] == "-gp" {
			showGroups = true
			showGroupsOptions = "p"
		}
		if os.Args[1] == "-gs" {
			showGroups = true
			showGroupsOptions = "s"
		}
		if os.Args[1] == "-gls" {
			showGroups = true
			showGroupsOptions = "ls"
		}
		if os.Args[1] == "-G" {
			searchGroup = true
		}
	}

	var cfg Configs
	dirname, err := os.UserHomeDir()
	if err != nil {
		log.Fatal(err)
	}
	dir := filepath.FromSlash(dirname + "/")

	errx := cleanenv.ReadConfig(dir+".luser_config.yml", &cfg)
	if errx != nil {
		log.Fatal(errx)
	}
	if cfg.FQDN == "" {
		fmt.Printf(colorRed+boldStart+"Invalid Server, fill the %s.luser_config.yml file with the necessary data"+styleReset+"\n", dir)
		os.Exit(0)
	}

	// TLS Connection
	//l, err := ConnectTLS(cfg)

	// Non-TLS Connection
	l, err := Connect(cfg, false)
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()

	if searchGroup {
		search := "(cn=" + searchText + ")"

		result, err := BindAndSearch(l, cfg, search, false)
		if err != nil {
			if cfg.Alt_FQDN != "" {
				fmt.Println(colorCyan + "Not found, search alternative...")
				l2, err := Connect(cfg, true)
				if err != nil {
					log.Fatal(err)
				}
				defer l2.Close()
				result, err = BindAndSearch(l2, cfg, search, true)
				if err != nil {
					log.Fatal(err)
				}
			} else {
				log.Fatal(err)
			}
		}
		membros := "\n " + displayUsers(result.Entries[0].GetAttributeValues("member"))
		createdAt := handleDate(result.Entries[0].GetAttributeValue("whenCreated"))
		whenChanged := handleDate(result.Entries[0].GetAttributeValue("whenChanged"))
		//result.Entries[0].PrettyPrint(2)
		fmt.Printf(colorBlue+"Group: "+colorYellow+boldStart+"%s"+styleReset+" \n", result.Entries[0].GetAttributeValue("sAMAccountName"))
		fmt.Printf(colorBlue+"Description: "+colorYellow+boldStart+"%s"+styleReset+" \n", result.Entries[0].GetAttributeValue("description"))
		fmt.Printf(colorBlue+"Email: "+colorYellow+boldStart+"%s"+styleReset+" \n", result.Entries[0].GetAttributeValue("mail"))
		fmt.Printf(colorBlue+"Created: "+colorYellow+boldStart+"%s"+styleReset+" \n", createdAt)
		fmt.Printf(colorBlue+"Changed: "+colorYellow+boldStart+"%s"+styleReset+" \n", whenChanged)
		fmt.Printf(colorBlue+"Members: "+boldStart+colorYellow+" %v\n"+styleReset, membros)

	} else {

		// Normal Bind and Search
		search := "(|(uid=" + searchText + ")(employeeID=" + searchText + ")(employeeNumber=" + searchText + ")(samaccountname=" + searchText + ")(mail=" + searchText + "))"

		result, err := BindAndSearch(l, cfg, search, false)
		if err != nil {
			if cfg.Alt_FQDN != "" {
				fmt.Println(colorCyan + "Not found, searching alternative...")
				l2, err := Connect(cfg, true)
				if err != nil {
					log.Fatal(err)
				}
				defer l2.Close()
				result, err = BindAndSearch(l2, cfg, search, true)
				if err != nil {
					log.Fatal(err)
				}
			} else {
				log.Fatal(err)
			}
		}

		corTempo := colorRed
		estadoConta := getAccountStatus(result.Entries[0].GetAttributeValue("userAccountControl"))
		passwordLastSet := result.Entries[0].GetAttributeValue("pwdLastSet")

		passwordAlterada := "N/A"
		expirationDays := 0
		if passwordLastSet != "" {
			if passwordLastSet == "0" {
				passwordAlterada = colorRed + "Expired"
			} else {
				passwordAlterada, expirationDays = ldapTimeToUnixTime(passwordLastSet, cfg)
			}
		}
		groups := ""
		if showGroups {
			groups = "\n " + displayGroups(result.Entries[0].GetAttributeValues("memberOf"), showGroupsOptions)
		}
		if expirationDays > 0 && expirationDays < 6 {
			corTempo = colorYellow
		} else if expirationDays > 5 {
			corTempo = colorGreen
		}

		isBlocked := colorGreen + "NO ✅"
		if result.Entries[0].GetAttributeValue("lockoutTime") != "0" && result.Entries[0].GetAttributeValue("lockoutTime") != "" {
			isBlocked = colorRed + "YES 🔐"
		}

		//result.Entries[0].PrettyPrint(2)

		fmt.Printf(colorBlue+"User: "+colorYellow+boldStart+"%s"+styleReset+" \n", result.Entries[0].GetAttributeValue("sAMAccountName"))
		fmt.Printf(colorBlue+"Name: "+colorYellow+boldStart+"%s"+styleReset+" \n", result.Entries[0].GetAttributeValue("displayName"))
		fmt.Printf(colorBlue+"Email: "+colorYellow+boldStart+"%s"+styleReset+" \n", result.Entries[0].GetAttributeValue("mail"))
		fmt.Printf(colorBlue+"Numbers: "+colorYellow+boldStart+"%s / %s\n"+styleReset, result.Entries[0].GetAttributeValue("employeeNumber"), result.Entries[0].GetAttributeValue("employeeID"))
		fmt.Printf(colorBlue+"Blocked: "+colorYellow+boldStart+"%s\n"+styleReset, isBlocked)
		fmt.Printf(colorBlue+"Status: "+colorYellow+boldStart+"%s\n"+styleReset, estadoConta)
		fmt.Printf(colorBlue+"Password Changed in: "+boldStart+colorYellow+" %s\n"+styleReset, passwordAlterada)
		fmt.Printf(colorBlue+"Password Expirest in: "+boldStart+corTempo+" %d days\n"+styleReset, expirationDays)
		fmt.Printf(colorBlue+"Wrong Passwords: "+boldStart+colorYellow+" %s\n"+styleReset, result.Entries[0].GetAttributeValue("badPwdCount"))
		fmt.Printf(colorBlue+"Script: "+boldStart+colorYellow+" %s\n"+styleReset, result.Entries[0].GetAttributeValue("scriptPath"))
		if showGroups {
			fmt.Printf(colorBlue+"Groups: "+boldStart+colorYellow+" %v\n"+styleReset, groups)
		}
	}
}

// Ldap Connection with TLS
func ConnectTLS(cfg Configs) (*ldap.Conn, error) {
	// You can also use IP instead of FQDN
	l, err := ldap.DialURL(fmt.Sprintf("ldaps://%s:636", cfg.FQDN))
	if err != nil {
		return nil, err
	}

	return l, nil
}

// Ldap Connection without TLS
func Connect(cfg Configs, alt bool) (*ldap.Conn, error) {
	useFQDN := cfg.FQDN
	usePort := cfg.Port
	// You can also use IP instead of FQDN
	if alt {
		useFQDN = cfg.Alt_FQDN
		usePort = cfg.Alt_Port
	}

	l, err := ldap.DialURL(fmt.Sprintf("ldap://%s:%d", useFQDN, usePort))
	if err != nil {
		return nil, err
	}
	return l, nil
}

// Normal Bind and Search
func BindAndSearch(l *ldap.Conn, cfg Configs, search string, alt bool) (*ldap.SearchResult, error) {
	useUser := cfg.BindUsername
	usePass := cfg.BindPassword
	useBase := cfg.BaseDN
	if alt {
		useUser = cfg.Alt_BindUsername
		usePass = cfg.Alt_BindPassword
		useBase = cfg.Alt_BaseDN
	}
	l.Bind(useUser, usePass)

	searchReq := ldap.NewSearchRequest(
		useBase,
		ldap.ScopeWholeSubtree, // you can also use ldap.ScopeBaseObject
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		search,
		[]string{},
		nil,
	)
	result, err := l.Search(searchReq)
	if err != nil {
		return nil, fmt.Errorf("error searching: %s", err)
	}

	if len(result.Entries) > 0 {
		return result, nil
	} else {
		return nil, fmt.Errorf("user not found")
	}
}

func handleDate(data string) (result string) {
	if data == "" {
		return ""
	}
	if len(data) < 14 {
		return data
	}
	result = data[0:4] + "-" + data[4:6] + "-" + data[6:8] + " " + data[8:10] + ":" + data[10:12] + ":" + data[12:14]
	return result
}

func displayGroups(groups []string, showGroupsOptions string) (result string) {
	for _, element := range groups {
		s := strings.Split(element, ",")
		if showGroupsOptions == "p" {
			//if default pipe just separate with pipes
			result = result + strings.Replace(s[0], "CN=", "", -1) + " | "
		} else if (showGroupsOptions == "s" || showGroupsOptions == "ls") && os.Args[3] != "" {
			//if search and 3rd param is available then either pipe (default) or list if "ls" is passed as 1rst param
			nGroup := strings.Replace(s[0], "CN=", "", -1)
			if strings.Contains(nGroup, os.Args[3]) {
				if showGroupsOptions == "ls" {
					result = result + "🗂  " + nGroup + " \n "
				} else {
					result = result + nGroup + " | "
				}
			}
		} else {
			//otherwise just list all groups by line
			result = result + "🗂  " + strings.Replace(s[0], "CN=", "", -1) + " \n "
		}
	}
	return result
}

func displayUsers(users []string) (result string) {
	for _, element := range users {
		s := strings.Split(element, ",")
		result = result + "👤  " + strings.Replace(s[0], "CN=", "", -1) + " \n "
	}
	return result
}

func ldapTimeToUnixTime(ldaptime string, cfg Configs) (tm string, expDays int) {
	if ldaptime == "" {
		tm = ""
		expDays = 0
	} else {
		converted, err := strconv.Atoi(ldaptime)
		secsAfterADEpoch := converted / 10000000
		ADToUnixConverter := ((1970-1601)*365 - 3 + math.Round((1970-1601)/4)) * 86400
		timeStamp := int(secsAfterADEpoch) - int(ADToUnixConverter)
		if err != nil {
			tm = "ERROR"
		} else {
			tmp := time.Unix(int64(timeStamp), 0)
			tx := tmp.UTC()
			tm = tx.String()
			timeAdded := tx.AddDate(0, 0, int(cfg.MaxPwdAge))
			currentTime := time.Now()
			timeDiff := timeAdded.Sub(currentTime).Hours() / 24
			roundedTime := math.RoundToEven(timeDiff)
			expDays = int(roundedTime)
		}
	}
	return tm, expDays
}

func getAccountStatus(code string) (resultado string) {
	//resultado := code
	switch code {
	case "1":
		resultado = "SCRIPT"
	case "2":
		resultado = colorRed + "ACCOUNTDISABLE ❌"
	case "8":
		resultado = "HOMEDIR_REQUIRED"
	case "16":
		resultado = colorRed + "LOCKOUT ❌"
	case "32":
		resultado = "PASSWD_NOTREQD"
	case "64":
		resultado = "PASSWD_CANT_CHANGE"
	case "128":
		resultado = "ENCRYPTED_TEXT_PWD_ALLOWED"
	case "256":
		resultado = "TEMP_DUPLICATE_ACCOUNT"
	case "512":
		resultado = colorGreen + "OK ✅"
	case "514":
		resultado = colorRed + "Disabled Account ❌"
	case "544":
		resultado = colorGreen + "Enabled, Password Not Required ✅"
	case "546":
		resultado = colorRed + "Disabled, Password Not Required ❌"
	case "2048":
		resultado = "INTERDOMAIN_TRUST_ACCOUNT"
	case "2080":
		resultado = "INTERDOMAIN_TRUST_ACCOUNT - Password Not Required"
	case "4096":
		resultado = "WORKSTATION_TRUST_ACCOUNT"
	case "8192":
		resultado = colorGreen + "SERVER_TRUST_ACCOUNT ✅"
	case "65536":
		resultado = "DONT_EXPIRE_PASSWORD"
	case "66048":
		resultado = colorGreen + "Enabled, Password Doesn’t Expire ✅"
	case "66050":
		resultado = colorRed + "Disabled, Password Doesn’t Expire ❌"
	case "66080":
		resultado = colorRed + "Disabled, Password Doesn’t Expire & Not Required ❌"
	case "66082":
		resultado = colorRed + "Disabled, Password Doesn’t Expire & Not Required ❌"
	case "131072":
		resultado = "MNS_LOGON_ACCOUNT"
	case "262144":
		resultado = "SMARTCARD_REQUIRED"
	case "262656":
		resultado = colorGreen + "Enabled, Smartcard Required ✅"
	case "262658":
		resultado = colorRed + "Disabled, Smartcard Required ❌"
	case "262690":
		resultado = colorRed + "Disabled, Smartcard Required, Password Not Required ❌"
	case "328194":
		resultado = colorRed + "Disabled, Smartcard Required, Password Doesn’t Expire ❌"
	case "328226":
		resultado = colorRed + "Disabled, Smartcard Required, Password Doesn’t Expire & Not Required ❌"
	case "524288":
		resultado = colorGreen + "TRUSTED_FOR_DELEGATION ✅"
	case "590336":
		resultado = colorGreen + "Enabled, User Cannot Change Password, Password Never Expires ✅"
	case "532480":
		resultado = "Domain controller"
	case "1048576":
		resultado = "NOT_DELEGATED"
	case "2097152":
		resultado = "USE_DES_KEY_ONLY"
	case "4194304":
		resultado = "DONT_REQ_PREAUTH"
	case "8388608":
		resultado = colorRed + "PASSWORD_EXPIRED ❌"
	case "16777216":
		resultado = "TRUSTED_TO_AUTH_FOR_DELEGATION"
	case "67108864":
		resultado = "PARTIAL_SECRETS_ACCOUNT"
	default:
		resultado = code
	}
	return resultado
}
