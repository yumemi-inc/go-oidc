package urls

import (
	"net/url"
)

func AppendQuery(u url.URL, query string) url.URL {
	if u.RawQuery != "" {
		u.RawQuery += "&" + query
	} else {
		u.RawQuery = query
	}

	return u
}

func AppendQueryString(urlString string, query string) (string, error) {
	u, err := url.Parse(urlString)
	if err != nil {
		return "", err
	}

	*u = AppendQuery(*u, query)

	return u.String(), nil
}
