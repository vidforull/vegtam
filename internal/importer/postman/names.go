package postman

import (
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

// translit spells Cyrillic letters in Latin, so that names in Russian or
// Ukrainian give readable file names.
var translit = map[rune]string{
	'а': "a", 'б': "b", 'в': "v", 'г': "g", 'ґ': "g", 'д': "d", 'е': "e", 'ё': "e", 'є': "ye",
	'ж': "zh", 'з': "z", 'и': "i", 'і': "i", 'ї': "yi", 'й': "y", 'к': "k", 'л': "l", 'м': "m",
	'н': "n", 'о': "o", 'п': "p", 'р': "r", 'с': "s", 'т': "t", 'у': "u", 'ф': "f", 'х': "kh",
	'ц': "ts", 'ч': "ch", 'ш': "sh", 'щ': "shch", 'ъ': "", 'ы': "y", 'ь': "", 'э': "e", 'ю': "yu",
	'я': "ya",
}

// ascii returns s with Cyrillic letters spelled in Latin and the case of
// each letter kept.
func ascii(s string) string {
	var b strings.Builder
	for _, r := range s {
		t, ok := translit[unicode.ToLower(r)]
		switch {
		case !ok:
			b.WriteRune(r)
		case unicode.IsUpper(r) && t != "":
			b.WriteString(strings.ToUpper(t[:1]) + t[1:])
		default:
			b.WriteString(t)
		}
	}
	return b.String()
}

var nonSlug = regexp.MustCompile(`[^a-z0-9]+`)

// maxSlug keeps file names well below the limits of file systems.
const maxSlug = 60

// slug returns a name for files and requests made from s: lower-case
// ASCII letters and digits joined by '-', or fallback if s has none.
func slug(s, fallback string) string {
	s = strings.Trim(nonSlug.ReplaceAllString(strings.ToLower(ascii(s)), "-"), "-")
	if len(s) > maxSlug {
		s = strings.TrimRight(s[:maxSlug], "-")
	}
	if s == "" {
		return fallback
	}
	return s
}

var (
	varName    = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]*$`)
	nonVarName = regexp.MustCompile(`[^A-Za-z0-9_.-]+`)
)

// variable returns a valid vegtam variable name made from the Postman
// variable name s.
func variable(s string) string {
	if varName.MatchString(s) {
		return s
	}
	s = nonVarName.ReplaceAllString(ascii(s), "_")
	if !varName.MatchString(s) {
		s = "_" + s
	}
	return s
}

// names hands out unique names within one scope: a directory, a file, a
// collection's variables.
type names map[string]bool

// unique returns name, or name-2, name-3 and so on if it is taken, and
// takes it.
func (n names) unique(name string) string {
	u := name
	for i := 2; n[u]; i++ {
		u = name + "-" + strconv.Itoa(i)
	}
	n[u] = true
	return u
}
