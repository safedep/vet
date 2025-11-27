package code

import (
	"github.com/safedep/code/core"
	"github.com/safedep/code/lang"

	"github.com/safedep/vet/pkg/common/logger"
)

func getAllLanguageCodeStrings() ([]string, error) {
	langs, err := lang.AllLanguages()
	if err != nil {
		return nil, err
	}
	var languageCodes []string
	for _, lang := range langs {
		languageCodes = append(languageCodes, string(lang.Meta().Code))
	}
	return languageCodes, nil
}

func getLanguagesFromCodes(languageCodes []string) ([]core.Language, error) {
	var languages []core.Language
	for _, languageCode := range languageCodes {
		language, err := lang.GetLanguage(languageCode)
		if err != nil {
			logger.Fatalf("failed to get language for code %s: %v", languageCode, err)
			return nil, err
		}
		languages = append(languages, language)
	}
	return languages, nil
}
