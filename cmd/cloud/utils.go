package cloud

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/safedep/vet/internal/auth"
	"github.com/safedep/vet/internal/ui"
	"gopkg.in/yaml.v2"
)

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpireIn    int    `json:"expires_in"`
	Scope       string `json:"scope"`
	IDToken     string `json:"id_token"`
	Tokentype   string `json:"token_type"`
}

func loadConfiguration() (auth.Config, error) {
	path, err := os.UserHomeDir()
	if err != nil {
		return auth.Config{}, err
	}

	path = filepath.Join(path, auth.HomeRelativeConfigPath())

	data, err := os.ReadFile(path)
	if err != nil {
		return auth.Config{}, err
	}

	var config auth.Config
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return auth.Config{}, fmt.Errorf("config deserialization failed: %w", err)
	}

	return config, nil
}

func persistConfiguration(config auth.Config) error {
	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("config serialization failed: %w", err)
	}

	path, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	path = filepath.Join(path, auth.HomeRelativeConfigPath())

	err = os.MkdirAll(filepath.Dir(path), os.ModePerm)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func getNewAccessTokenAndPersistIt(config auth.Config) error {
	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", config.CloudRefreshToken)
	data.Set("client_id", auth.CloudIdentityServiceClientId())

	req, _ := http.NewRequest("POST", auth.CloudIdentityServiceTokenUrl(), strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		ui.PrintError("❌ Oops! Getting a new access token failed. Please use 'vet cloud login' command to get new access and refresh token")
		return fmt.Errorf("refresh failed: %s", string(body))
	}

	var result TokenResponse

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}

	config.CloudAccessToken = result.AccessToken
	config.CloudAccessTokenUpdatedAt = time.Now()

	return persistConfiguration(config)
}

// checkIfNewAccessTokenRequired does two level of check before trying to get the new access token
//  1. Using CloudAccessTokenUpdatedAt field it check if the last time it was updated
//     is less than equal to 10 hrs or not(Here 10hrs was taken because it was observer that most of the JWT token had similar expiry time)
//  2. It will parse the JWT token to get the expiry time and then check for it expiry
func checkIfNewAccessTokenRequired(config auth.Config) (bool, error) {
	if time.Since(config.CloudAccessTokenUpdatedAt) <= 10*time.Hour {
		return false, nil
	}

	claims := jwt.MapClaims{}
	_, _, err := jwt.NewParser().ParseUnverified(config.CloudAccessToken, claims)
	if err != nil {
		return false, err
	}

	accessTokenExpiryTime, err := strconv.ParseInt(fmt.Sprintf("%.0f", claims["exp"]), 10, 64)
	if err != nil {
		return false, err
	}

	return time.Now().Unix() > accessTokenExpiryTime, nil
}

func getNewAccessTokenUsingRefreshTokenIfCurrentIsExpired() error {
	config, err := loadConfiguration()
	if err != nil {
		return err
	}

	isRequired, err := checkIfNewAccessTokenRequired(config)
	if err != nil {
		return err
	}

	if !isRequired {
		return nil
	}

	return getNewAccessTokenAndPersistIt(config)
}
