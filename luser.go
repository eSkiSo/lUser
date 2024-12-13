package main

import (
	"flag"
	"fmt"
	"log"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"

	"github.com/go-ldap/ldap/v3"
	"github.com/ilyakaznacheev/cleanenv"
)

const (
	Version     = "0.14"
	colorRed    = "\033[91m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[36m" //was 34
	colorCyan   = "\033[34m" //was 36
	italicStart = "\033[3m"
	boldStart   = "\033[1m"
	styleReset  = "\033[0m"
)

type Configs struct {
	EncriptPassword  bool `yaml:"encryptpassword" env:"EncryptPassword" env-default:"false"`
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

type SID struct {
	RevisionLevel     int
	SubAuthorityCount int
	Authority         int
	SubAuthorities    []int
	RelativeID        *int
}

func DecodeSID(b []byte) string {

	var sid SID

	sid.RevisionLevel = int(b[0])
	sid.SubAuthorityCount = int(b[1]) & 0xFF

	for i := 2; i <= 7; i++ {
		sid.Authority = sid.Authority | int(b[i])<<(8*(5-(i-2)))
	}

	var offset = 8
	var size = 4
	for i := 0; i < sid.SubAuthorityCount; i++ {
		var subAuthority int
		for k := 0; k < size; k++ {
			subAuthority = subAuthority | (int(b[offset+k])&0xFF)<<(8*k)
		}
		sid.SubAuthorities = append(sid.SubAuthorities, subAuthority)
		offset += size
	}

	s := fmt.Sprintf("S-%d-%d", sid.RevisionLevel, sid.Authority)
	for _, v := range sid.SubAuthorities {
		s += fmt.Sprintf("-%d", v)
	}
	return s
}

func printHelp() {
	fmt.Println(colorCyan + boldStart + "lUser LDAP Cli")
	fmt.Println("> luser [optional argument] <user|partial user|number|email|partial name> <optional search if -gsl or -gs>\n " + styleReset)
	fmt.Println(colorBlue + "Search User" + styleReset)
	fmt.Println(colorYellow + "> luser <user|partial user|number|email|partial name|sid> \n " + styleReset)
	fmt.Println(colorBlue + "Search User in both servers" + styleReset)
	fmt.Println(colorYellow + "> luser -a <user|partial user|number|email|partial name|sid> \n " + styleReset)
	fmt.Println(colorBlue + "Search User with Groups" + styleReset)
	fmt.Println(colorYellow + "> luser -g <user|number|email|partial name> " + colorCyan + italicStart + " Separated by |" + styleReset)
	fmt.Println(colorYellow + "> luser -gl <user|number|email|partial name> " + colorCyan + italicStart + " Separated by new line \n " + styleReset)
	fmt.Println(colorBlue + "Search User with search/filter of group")
	fmt.Println(colorYellow + "> luser -gs <user|number|email|partial name> <text to search> " + colorCyan + italicStart + " Separated by |" + styleReset)
	fmt.Println(colorYellow + "> luser -gsl <user|number|email|partial name> <text to search> " + colorCyan + italicStart + " Separated by new line \n " + styleReset)
	fmt.Println(colorBlue + "Search Groups / List Members")
	fmt.Println(colorYellow + "> luser -G <group|partial group name> \n")
	fmt.Println(colorBlue + "Create encrypted password")
	fmt.Println(colorYellow + "> luser -e <password to encrypt>")
	fmt.Println(colorBlue + "Version")
	fmt.Println(colorYellow + "> luser -v")
}

// Look, i've found a flag pkg
var showGroups = flag.Bool("g", false, "show groups")
var searchGroup = flag.Bool("G", false, "search group")
var searchAlternative = flag.Bool("a", false, "search alternative server only")
var encryptPassword = flag.Bool("e", false, "use this to get an encrypted password to use on configs")
var showGroupsList = flag.Bool("gl", false, "show groups in list")
var showGroupsPipe = flag.Bool("gp", false, "show groups pipped")
var showGroupsSearch = flag.Bool("gs", false, "show groups with search")
var showGroupsSearchList = flag.Bool("gls", false, "show groups with search in list")
var showHelp = flag.Bool("h", false, "show help")
var showVersion = flag.Bool("v", false, "show version")
var bytes = []byte{35, 46, 57, 24, 85, 35, 24, 74, 87, 35, 88, 98, 66, 32, 14, 05}
const MySecret string = "abc&h*~#^25#s2^=)^^7%b3g"

func init() {
	flag.Parse()
}

func main() {

	if len(os.Args) < 2 {
		fmt.Print(colorRed + boldStart + "You must supply a search parameter (user or group name if -G)" + styleReset + "\n")
		printHelp()
		os.Exit(0)
	}

	searchText := os.Args[1]
	showGroupsOptions := "p"

	if *encryptPassword {
		searchText = os.Args[2]
		encText, err := Encrypt(searchText, MySecret)
		if err != nil {
			fmt.Println("Error encrypting your classified text: ", err)
		}
		fmt.Printf(colorCyan+boldStart+"lUser Encrypted Password (%s) :\033[0m %s \n"+styleReset, searchText, encText)
		os.Exit(0)
	}

	if *showHelp {
		printHelp()
		os.Exit(0)
	}

	if *showVersion {
		fmt.Printf(colorCyan+boldStart+"lUser LDAP Cli v %v \n"+styleReset, Version)
		os.Exit(0)
	}

	if *showGroupsList {
		searchText = os.Args[2]
		showGroupsOptions = "l"
		*showGroups = true
	}

	if *searchAlternative {
		searchText = os.Args[2]
	}

	if *showGroupsPipe {
		searchText = os.Args[2]
		showGroupsOptions = "p"
		*showGroups = true
	}

	if *showGroups {
		searchText = os.Args[2]
	}

	if *showGroupsSearch {
		searchText = os.Args[2]
		showGroupsOptions = "s"
		*showGroups = true
	}

	if *showGroupsSearchList {
		searchText = os.Args[2]
		showGroupsOptions = "ls"
		*showGroups = true
	}

	if *searchGroup {
		searchText = os.Args[2]
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

	//handle encryting
	if cfg.EncriptPassword {
		//fmt.Println(colorCyan+italicStart + "Decripting password.." + styleReset)
		decText, err := Decrypt(cfg.BindPassword, MySecret)
		if err != nil {
			fmt.Println(colorRed+"Error decrypting your encrypted password: ", err)
		}
		cfg.BindPassword = decText;

		decText, err = Decrypt(cfg.Alt_BindPassword, MySecret)
		if err != nil {
			fmt.Println(colorRed+"Error decrypting your alternative encrypted password: ", err)
		}
		cfg.Alt_BindPassword = decText;
	}
	//fmt.Println(cfg.BindPassword)

	// TLS Connection
	//l, err := ConnectTLS(cfg)

	// Non-TLS Connection
	l, err := Connect(cfg, false)
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()

	if *searchGroup {
		search := "(cn=*" + searchText + "*)"

		fmt.Println(search)

		result, err := BindAndSearch(l, cfg, search, false)
		if err != nil || *searchAlternative {

			if err == nil && *searchAlternative {
				//output first search
				outputGroupResults(result)
			}

			if cfg.Alt_FQDN != "" {
				fmt.Println(colorCyan + "Searching alternative...")
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

		//output
		outputGroupResults(result)

	} else {

		// Normal Bind and Search
		search := "(|(uid=" + searchText + ")(employeeID=" + searchText + ")(employeeNumber=" + searchText + ")(samaccountname=" + searchText + ")(samaccountname=" + searchText + "*)(mail=" + searchText + ")(displayName=*" + searchText + "*)(objectSid=" + searchText + "))"

		result, err := BindAndSearch(l, cfg, search, false)
		if err != nil || *searchAlternative {

			if err == nil && *searchAlternative {
				//output first search
				outPutUserResults(result, showGroupsOptions, cfg)
			}

			if cfg.Alt_FQDN != "" {
				fmt.Println(colorCyan + "Searching alternative...")
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
		outPutUserResults(result, showGroupsOptions, cfg)
	}
}

func Encode(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

func Decode(s string) []byte {
	data, err := base64.StdEncoding.DecodeString(s)
 	if err != nil {
  		panic(err)
 	}
 	return data
}
// Encrypt method is to encrypt or hide any classified text
func Encrypt(text, MySecret string) (string, error) {
	block, err := aes.NewCipher([]byte(MySecret))
	if err != nil {
		return "", err
	}
	plainText := []byte(text)
	cfb := cipher.NewCFBEncrypter(block, bytes)
	cipherText := make([]byte, len(plainText))
	cfb.XORKeyStream(cipherText, plainText)
	return Encode(cipherText), nil
}

// Decrypt method is to extract back the encrypted text
func Decrypt(text, MySecret string) (string, error) {
	block, err := aes.NewCipher([]byte(MySecret))
	if err != nil {
		return "", err
	}

	cipherText := Decode(text)
	cfb := cipher.NewCFBDecrypter(block, bytes)
	plainText := make([]byte, len(cipherText))
	cfb.XORKeyStream(plainText, cipherText)
	return string(plainText), nil
}

func outPutUserResults(result *ldap.SearchResult, showGroupsOptions string, cfg Configs) (written bool) {
	corTempo := colorRed
	estadoConta := ""
	passwordLastSet := ""
	passwordAlterada := "N/A"
	ignoreExpireDate := false
	expirationDays := 0
	groups := ""
	isBlocked := colorGreen + "NO ✅"

	fmt.Printf(colorCyan+"Found %d user(s) \n", len(result.Entries))

	for _, resultado := range result.Entries {

		corTempo = colorRed
		estadoConta = getAccountStatus(resultado.GetAttributeValue("userAccountControl"))
		ignoreExpireDate = getPasswordExpireIgnore(resultado.GetAttributeValue("userAccountControl"))
		passwordLastSet = resultado.GetAttributeValue("pwdLastSet")

		passwordAlterada = "N/A"
		expirationDays = 0
		if passwordLastSet == "0" {
			passwordAlterada = colorRed + "Expired"
		} else {
			passwordAlterada, expirationDays = ldapTimeToUnixTime(passwordLastSet, cfg)
		}

		lastLogon, _ := ldapTimeToUnixTime(resultado.GetAttributeValue("lastLogon"), cfg)
		groups = ""
		if *showGroups {
			groups = "\n " + displayGroups(resultado.GetAttributeValues("memberOf"), showGroupsOptions)
		}
		if expirationDays > 0 && expirationDays < 6 {
			corTempo = colorYellow
		} else if expirationDays > 5 {
			corTempo = colorGreen
		}

		if ignoreExpireDate {
			expirationDays = 0
			corTempo = colorGreen
		}

		isBlocked = colorGreen + "NO ✅"
		if resultado.GetAttributeValue("lockoutTime") != "0" && resultado.GetAttributeValue("lockoutTime") != "" {
			isBlocked = colorRed + "YES 🔐"
		}

		accountExpires := "Never"
		corExpires := colorGreen
		if resultado.GetAttributeValue("accountExpires") != "0" && resultado.GetAttributeValue("accountExpires") != "" {
			ae, expiresIn := ldapTimeToUnixTimeDates(resultado.GetAttributeValue("accountExpires"))
			if(expiresIn > 0 && expiresIn < 10000) {
				if expiresIn < 1 {
					corExpires = colorRed
				} else if(expiresIn < 27) {
					corExpires = colorYellow
				}
				accountExpires = fmt.Sprintf(corExpires+"%d " + styleReset + "days (%s)", expiresIn, ae[:16])
			} else {
				if(expiresIn < 10000) {
					accountExpires = ae
				}
			}
		}

		distinguishedName := strings.Split(resultado.GetAttributeValue("distinguishedName"), ",")
		tempDomain := ""
		for _, element := range distinguishedName {
			if strings.HasPrefix(element, "DC=") {
				if tempDomain == "" {
					tempDomain = strings.Replace(element, "DC=", "", -1)
				} else {
					tempDomain = tempDomain + "." + strings.Replace(element, "DC=", "", -1)
				}
				
			}
		}
		//resultado.PrettyPrint(2)

		fmt.Printf(colorBlue+"User: "+colorYellow+boldStart+"%s"+styleReset+" \n", resultado.GetAttributeValue("sAMAccountName"))
		fmt.Printf(colorBlue+"Name: "+colorYellow+boldStart+"%s"+styleReset+" \n", resultado.GetAttributeValue("displayName"))
		fmt.Printf(colorBlue+"Email: "+colorYellow+boldStart+"%s"+styleReset+" \n", resultado.GetAttributeValue("mail"))
		fmt.Printf(colorBlue+"CN: "+colorYellow+boldStart+"%s"+styleReset+" \n", resultado.GetAttributeValue("cn"))
		fmt.Printf(colorBlue+"Department: "+boldStart+colorYellow+" %s\n"+styleReset, resultado.GetAttributeValue("department"))
		fmt.Printf(colorBlue+"Numbers: "+colorYellow+boldStart+"%s / %s\n"+styleReset, resultado.GetAttributeValue("employeeNumber"), resultado.GetAttributeValue("employeeID"))
		fmt.Printf(colorBlue+"Blocked: "+colorYellow+boldStart+"%s\n"+styleReset, isBlocked)
		fmt.Printf(colorBlue+"Status: "+colorYellow+boldStart+"%s\n"+styleReset, estadoConta)
		fmt.Printf(colorBlue+"Account Expires: "+colorYellow+boldStart+"%s\n"+styleReset, accountExpires)
		fmt.Printf(colorBlue+"Password Changed in: "+boldStart+colorYellow+" %s\n"+styleReset, passwordAlterada)
		if !ignoreExpireDate {
			fmt.Printf(colorBlue+"Password Expires in: "+boldStart+corTempo+" %d days\n"+styleReset, expirationDays)
		}
		fmt.Printf(colorBlue+"Last Logon: "+boldStart+colorYellow+" %s\n"+styleReset, lastLogon)
		fmt.Printf(colorBlue+"Wrong Passwords: "+boldStart+colorYellow+" %s\n"+styleReset, resultado.GetAttributeValue("badPwdCount"))
		fmt.Printf(colorBlue+"Script: "+boldStart+colorYellow+" %s\n"+styleReset, resultado.GetAttributeValue("scriptPath"))
		fmt.Printf(colorBlue+"Domain: "+boldStart+colorYellow+" %s\n"+styleReset, tempDomain)
		fmt.Printf(colorBlue+"DN: "+boldStart+colorYellow+" %s\n"+styleReset, resultado.GetAttributeValue("distinguishedName"))		
		fmt.Printf(colorBlue+"User Principal Name: "+boldStart+colorYellow+" %s\n"+styleReset, resultado.GetAttributeValue("userPrincipalName"))
		objectSid := resultado.GetRawAttributeValue("objectSid")
		sidCheck := resultado.GetAttributeValue("objectSid")
		sid := ""
		if sidCheck != "" {
			sid = DecodeSID(objectSid)
		}
		fmt.Printf(colorBlue+"SID: "+boldStart+colorYellow+" %s\n"+styleReset, sid)
		if *showGroups {
			fmt.Printf(colorBlue+"Groups: "+boldStart+colorYellow+" %v\n"+styleReset, groups)
		}
		fmt.Println("--------")
	}
	return true
}

func outputGroupResults(result *ldap.SearchResult) (written bool) {
	membros := ""
	createdAt := ""
	whenChanged := ""

	fmt.Printf(colorCyan+"Found %d group(s) \n", len(result.Entries))

	for _, resultado := range result.Entries {
		membros = "\n " + displayUsers(resultado.GetAttributeValues("member"))
		createdAt = handleDate(resultado.GetAttributeValue("whenCreated"))
		whenChanged = handleDate(resultado.GetAttributeValue("whenChanged"))
		//resultado.PrettyPrint(2)
		fmt.Printf(colorBlue+"Group: "+colorYellow+boldStart+"%s"+styleReset+" \n", resultado.GetAttributeValue("sAMAccountName"))
		fmt.Printf(colorBlue+"Description: "+colorYellow+boldStart+"%s"+styleReset+" \n", resultado.GetAttributeValue("description"))
		fmt.Printf(colorBlue+"CN: "+colorYellow+boldStart+"%s"+styleReset+" \n", resultado.GetAttributeValue("cn"))
		fmt.Printf(colorBlue+"DN: "+colorYellow+boldStart+"%s"+styleReset+" \n", resultado.GetAttributeValue("distinguishedName"))
		fmt.Printf(colorBlue+"Email: "+colorYellow+boldStart+"%s"+styleReset+" \n", resultado.GetAttributeValue("mail"))
		fmt.Printf(colorBlue+"Created: "+colorYellow+boldStart+"%s"+styleReset+" \n", createdAt)
		fmt.Printf(colorBlue+"Changed: "+colorYellow+boldStart+"%s"+styleReset+" \n", whenChanged)
		fmt.Printf(colorBlue+"Members: "+boldStart+colorYellow+" %v\n"+styleReset, membros)
		fmt.Println("--------")
	}

	return true
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
		return nil, fmt.Errorf("not found")
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
		} else if (showGroupsOptions == "s" || showGroupsOptions == "ls") && len(os.Args) > 3 && os.Args[3] != "" {
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
			if (showGroupsOptions == "l" || showGroupsOptions == "ls") {
				result = result + "🗂  " + strings.Replace(s[0], "CN=", "", -1) + " \n "
			} else {
				result = result + strings.Replace(s[0], "CN=", "", -1)  + " | "
			}
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

func ldapTimeToUnixTimeDates(ldaptime string) (tm string, expDays int) {
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
			timeAdded := tmp //tx.AddDate(0, 0, int(cfg.MaxPwdAge))
			currentTime := time.Now()
			timeDiff := timeAdded.Sub(currentTime).Hours() / 24
			roundedTime := math.RoundToEven(timeDiff)
			expDays = int(roundedTime)
		}
	}
	return tm, expDays
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

func getPasswordExpireIgnore(code string) (resultado bool) {
	//resultado := code
	switch code {
	case "32":
		resultado = true
	case "64":
		resultado = true
	case "544":
		resultado = true
	case "546":
		resultado = true
	case "2080":
		resultado = true
	case "65536":
		resultado = true
	case "66048":
		resultado = true
	case "66050":
		resultado = true
	case "66080":
		resultado = true
	case "66082":
		resultado = true
	case "262690":
		resultado = true
	case "328194":
		resultado = true
	case "328226":
		resultado = true
	case "590336":
		resultado = true
	default:
		resultado = false
	}
	return resultado
}
