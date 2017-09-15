// Copyright (c) 2016-present Mattermost, Inc. All Rights Reserved.
// See License.txt for license information.

package utils

import (
	"crypto/md5"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"

	l4g "github.com/alecthomas/log4go"

	"github.com/mattermost/platform/model"
)

var IsLicensed bool = false
var License *model.License = &model.License{
	Features: new(model.Features),
}
var ClientLicense map[string]string = map[string]string{"IsLicensed": "false"}

func LoadLicense(licenseBytes []byte) {
	if success, licenseStr := ValidateLicense(licenseBytes); success {
		license := model.LicenseFromJson(strings.NewReader(licenseStr))
		SetLicense(license)
		return
	}

	l4g.Warn(T("utils.license.load_license.invalid.warn"))
}

func SetLicense(license *model.License) bool {
	license.Features.SetDefaults()

	if !license.IsExpired() {
		License = license
		IsLicensed = true
		ClientLicense = getClientLicense(license)
		ClientCfg = getClientConfig(Cfg)
		return true
	}

	return false
}

func RemoveLicense() {
	License = &model.License{}
	IsLicensed = false
	ClientLicense = getClientLicense(License)
	ClientCfg = getClientConfig(Cfg)
}

func ValidateLicense(signed []byte) (bool, string) {
	return true, string(signed[:])
}

func GetAndValidateLicenseFileFromDisk() (*model.License, []byte) {
	fileName := GetLicenseFileLocation(*Cfg.ServiceSettings.LicenseFileLocation)

	if _, err := os.Stat(fileName); err != nil {
		l4g.Debug("We could not find the license key in the database or on disk at %v", fileName)
		return nil, nil
	}

	l4g.Info("License key has not been uploaded.  Loading license key from disk at %v", fileName)
	licenseBytes := GetLicenseFileFromDisk(fileName)

	if success, licenseStr := ValidateLicense(licenseBytes); !success {
		l4g.Error("Found license key at %v but it appears to be invalid.", fileName)
		return nil, nil
	} else {
		l4g.Info("license", licenseStr)
		return model.LicenseFromJson(strings.NewReader(licenseStr)), licenseBytes
	}
}

func GetLicenseFileFromDisk(fileName string) []byte {
	file, err := os.Open(fileName)
	if err != nil {
		l4g.Error("Failed to open license key from disk at %v err=%v", fileName, err.Error())
		return nil
	}
	defer file.Close()

	licenseBytes, err := ioutil.ReadAll(file)
	if err != nil {
		l4g.Error("Failed to read license key from disk at %v err=%v", fileName, err.Error())
		return nil
	}

	return licenseBytes
}

func GetLicenseFileLocation(fileLocation string) string {
	if fileLocation == "" {
		configDir, _ := FindDir("config")
		return configDir + "mattermost.mattermost-license"
	} else {
		return fileLocation
	}
}

func getClientLicense(l *model.License) map[string]string {
	props := make(map[string]string)

	props["IsLicensed"] = strconv.FormatBool(IsLicensed)

	if IsLicensed {
		props["Id"] = l.Id
		props["Users"] = strconv.Itoa(*l.Features.Users)
		props["LDAP"] = strconv.FormatBool(*l.Features.LDAP)
		props["MFA"] = strconv.FormatBool(*l.Features.MFA)
		props["SAML"] = strconv.FormatBool(*l.Features.SAML)
		props["Cluster"] = strconv.FormatBool(*l.Features.Cluster)
		props["Metrics"] = strconv.FormatBool(*l.Features.Metrics)
		props["GoogleOAuth"] = strconv.FormatBool(*l.Features.GoogleOAuth)
		props["Office365OAuth"] = strconv.FormatBool(*l.Features.Office365OAuth)
		props["Compliance"] = strconv.FormatBool(*l.Features.Compliance)
		props["CustomBrand"] = strconv.FormatBool(*l.Features.CustomBrand)
		props["MHPNS"] = strconv.FormatBool(*l.Features.MHPNS)
		props["PasswordRequirements"] = strconv.FormatBool(*l.Features.PasswordRequirements)
		props["Announcement"] = strconv.FormatBool(*l.Features.Announcement)
		props["IssuedAt"] = strconv.FormatInt(l.IssuedAt, 10)
		props["StartsAt"] = strconv.FormatInt(l.StartsAt, 10)
		props["ExpiresAt"] = strconv.FormatInt(l.ExpiresAt, 10)
		props["Name"] = l.Customer.Name
		props["Email"] = l.Customer.Email
		props["Company"] = l.Customer.Company
		props["PhoneNumber"] = l.Customer.PhoneNumber
		props["EmailNotificationContents"] = strconv.FormatBool(*l.Features.EmailNotificationContents)
	}

	return props
}

func GetClientLicenseEtag(useSanitized bool) string {
	value := ""

	lic := ClientLicense

	if useSanitized {
		lic = GetSanitizedClientLicense()
	}

	for k, v := range lic {
		value += fmt.Sprintf("%s:%s;", k, v)
	}

	return model.Etag(fmt.Sprintf("%x", md5.Sum([]byte(value))))
}

func GetSanitizedClientLicense() map[string]string {
	sanitizedLicense := make(map[string]string)

	for k, v := range ClientLicense {
		sanitizedLicense[k] = v
	}

	if IsLicensed {
		delete(sanitizedLicense, "Id")
		delete(sanitizedLicense, "Name")
		delete(sanitizedLicense, "Email")
		delete(sanitizedLicense, "PhoneNumber")
		delete(sanitizedLicense, "IssuedAt")
		delete(sanitizedLicense, "StartsAt")
		delete(sanitizedLicense, "ExpiresAt")
	}

	return sanitizedLicense
}
