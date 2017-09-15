package imports

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	l4g "github.com/alecthomas/log4go"

	"github.com/go-ldap/ldap"
	"github.com/mattermost/platform/app"
	"github.com/mattermost/platform/einterfaces"
	"github.com/mattermost/platform/model"
	"github.com/mattermost/platform/utils"
)

type LdapInterfaceImpl struct {
}

func (li *LdapInterfaceImpl) DoLogin(id string, password string) (*model.User, *model.AppError) {
	_, err := LdapLogin(id, password)
	if err != nil {
		return nil, model.NewAppError("login", "api.user.login_ldap.not_available.app_error", nil, err.Error(), http.StatusNotImplemented)
	}
	return app.GetUserByAuth(&id, model.USER_AUTH_SERVICE_LDAP)
}
func (li *LdapInterfaceImpl) GetUser(id string) (*model.User, *model.AppError) {
	return app.GetUserByAuth(&id, model.USER_AUTH_SERVICE_LDAP)
}
func (li *LdapInterfaceImpl) CheckPassword(id string, password string) *model.AppError {
	_, err := LdapLogin(id, password)
	if err != nil {
		return model.NewAppError("login", "api.user.login_ldap.not_available.app_error", nil, err.Error(), http.StatusNotImplemented)
	}
	return nil
}
func (li *LdapInterfaceImpl) SwitchToLdap(userId, ldapId, ldapPassword string) *model.AppError {
	return nil
}
func (li *LdapInterfaceImpl) ValidateFilter(filter string) *model.AppError {
	return nil
}
func (li *LdapInterfaceImpl) Syncronize() *model.AppError {
	return nil
}
func (li *LdapInterfaceImpl) StartLdapSyncJob() {
	return
}
func (li *LdapInterfaceImpl) SyncNow() {
	res, err := LdapSearch(0, *utils.Cfg.LdapSettings.UserFilter)
	if err != nil {
		l4g.Error("Unable to create user. Error: " + err.Error())
	}

	for _, entry := range res.Entries {
		user := NewUserFromLdapEntry(entry)

		l4g.Info(user.ToJson())

		_, err := app.CreateUser(user)
		if err != nil {
			l4g.Error("Unable to create user. Error: " + err.Error())
		}
	}
	return
}
func (li *LdapInterfaceImpl) RunTest() *model.AppError {
	res, err := LdapSearch(5, *utils.Cfg.LdapSettings.UserFilter)
	if err != nil {
		return model.NewAppError("login", "api.user.login_ldap.not_available.app_error", nil, err.Error(), http.StatusNotImplemented)
	}
	l4g.Info("LDAP search: OK")
	for _, entry := range res.Entries {
		l4g.Info(entry.DN)
	}
	return nil
}
func (li *LdapInterfaceImpl) GetAllLdapUsers() ([]*model.User, *model.AppError) {
	return nil, nil
}

func LdapConnect(username string, password string) (*ldap.Conn, error) {
	l, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", *utils.Cfg.LdapSettings.LdapServer, *utils.Cfg.LdapSettings.LdapPort))
	if err != nil {
		return l, err
	}
	l4g.Info("LDAP connect: OK")

	err = l.Bind(username, password)
	if err != nil {
		return l, err
	}
	l4g.Info("LDAP bind: OK")
	return l, nil
}

func LdapBindConnect() (*ldap.Conn, error) {
	return LdapConnect(*utils.Cfg.LdapSettings.BindUsername, *utils.Cfg.LdapSettings.BindPassword)
}

func NewUserFromLdapEntry(entry *ldap.Entry) *model.User {
	user := &model.User{
		AuthService: model.USER_AUTH_SERVICE_LDAP,
	}
	if locale := *utils.Cfg.LocalizationSettings.DefaultServerLocale; locale != "" {
		user.Locale = locale
	}
	if id := *utils.Cfg.LdapSettings.IdAttribute; id != "" {
		uid := entry.GetAttributeValue(id)
		user.AuthData = &uid
	}
	if username := *utils.Cfg.LdapSettings.UsernameAttribute; username != "" {
		user.Username = entry.GetAttributeValue(username)
	}
	if email := *utils.Cfg.LdapSettings.EmailAttribute; email != "" {
		user.Email = entry.GetAttributeValue(email)
	}
	if nickname := *utils.Cfg.LdapSettings.NicknameAttribute; nickname != "" {
		user.Nickname = entry.GetAttributeValue(nickname)
	}
	if firstName := *utils.Cfg.LdapSettings.FirstNameAttribute; firstName != "" {
		user.FirstName = entry.GetAttributeValue(firstName)
	}
	if lastName := *utils.Cfg.LdapSettings.LastNameAttribute; lastName != "" {
		user.LastName = entry.GetAttributeValue(lastName)
	}
	if position := *utils.Cfg.LdapSettings.PositionAttribute; position != "" {
		user.Position = entry.GetAttributeValue(position)
	}
	return user
}

func GetLdapAttributes() []string {
	attributesMap := map[string]bool{}
	attributesMap[*utils.Cfg.LdapSettings.FirstNameAttribute] = true
	attributesMap[*utils.Cfg.LdapSettings.LastNameAttribute] = true
	attributesMap[*utils.Cfg.LdapSettings.EmailAttribute] = true
	attributesMap[*utils.Cfg.LdapSettings.UsernameAttribute] = true
	attributesMap[*utils.Cfg.LdapSettings.NicknameAttribute] = true
	attributesMap[*utils.Cfg.LdapSettings.IdAttribute] = true
	attributesMap[*utils.Cfg.LdapSettings.PositionAttribute] = true
	attributes := []string{}
	for key := range attributesMap {
		if key != "" {
			attributes = append(attributes, key)
		}
	}
	return attributes
}

func LdapSearch(sizeLimit int, filter string) (*ldap.SearchResult, error) {
	l, err := LdapBindConnect()
	if err != nil {
		return nil, err
	}
	defer l.Close()

	attributes := GetLdapAttributes()
	l4g.Info(strings.Join(attributes, ","))

	req := ldap.NewSearchRequest(*utils.Cfg.LdapSettings.BaseDN, ldap.ScopeWholeSubtree, ldap.DerefAlways, sizeLimit, 0, false, filter, attributes, nil)
	return l.Search(req)
}

func LdapLogin(uid string, password string) (*ldap.Entry, error) {
	filter := "(" + *utils.Cfg.LdapSettings.IdAttribute + "=" + uid + ")"
	res, err := LdapSearch(0, filter)
	if err != nil {
		return nil, err
	}

	if len(res.Entries) != 1 {
		return nil, errors.New("User does not exist or too many entries returned")
	}

	entry := res.Entries[0]

	l, err := LdapConnect(entry.DN, password)
	if err != nil {
		return nil, err
	}
	defer l.Close()

	return entry, nil
}

func init() {
	einterfaces.RegisterLdapInterface(&LdapInterfaceImpl{})
}
