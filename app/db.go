package app

type Application struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`

	Files []string `yaml:"files"`

	Root       string `yaml:"root"`
	Repository string `yaml:"repository"`
}

type DB struct {
	Application map[string]Application `yaml:"application"`
}
