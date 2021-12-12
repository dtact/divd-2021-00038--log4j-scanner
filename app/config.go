package app

type config struct {
	debug        bool
	verbose      bool
	dry          bool
	numThreads   int
	maxRedirects int
	rate         int

	userAgent string

	//	targetURL *url.URL

	suffixes []string
}
