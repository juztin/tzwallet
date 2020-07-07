package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"regexp"
	"runtime"
	"strings"
	"syscall"

	"github.com/juztin/tzwallet"
	"github.com/juztin/tzwallet/cmd"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/ssh/terminal"
)

const (
	VALID_CHARS       = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	VALID_FIRST_CHARS = "KLMNPQRSTUVWXYZabcdefghi"
)

type MatchFunc func(s string) bool

type VanityFunc func(ctx context.Context, matches MatchFunc, matchCh chan<- Wallet, countCh chan<- struct{}, errCh chan<- error)

type Wallet struct {
	Address  string
	Mnemonic string
	Pk       string
	Sk       string
}

func usage() {
	fmt.Printf(`Tezos Wallet Generation

Usage:
  %[1]s [command] {args}

Available Commands:
  new                       Creates a new wallet from the given arguments.
                             (password will be prompted)
               --mnemonic      BIP39 mnemonic phrase
               --password   File containing a password to use (prompt excluded)
  vanity                     Generates a vanity wallet, matching the provided arguments.
                             (password will be prompted)
               --prefix        prefix of address, after 'tz1{prefix}...'
               --suffix        suffix of address, after 'tz1...{suffix}'
               --regexp     Regular expression to match.
                            CAUTION, there is not validation, allowing invalid expressions to run forever.
  version                    Display the %[1]s version

Examples:
  new
    Create a new address, using the password from a file

      %[1]s new -password secret.txt

    Recreate address from mnemonic

      %[1]s new -mnemonic "...mnemonic phrase..."

  vanity
    Find an address that starts with 'tz1ii...'

      %[1]s vanity -prefix ii

    Find an address that ends with 'tz1...jj

      %[1]s vanity -suffix jj

    Find an address that starts with 'tz1ii...', and ends with '...jj'

      %[1]s vanity -prefix ii -suffix jj 

    Find an address by regex

      %[1]s vanity -regex "^V[Aa][Nn]"
`, os.Args[0])
}

func (w Wallet) String() string {
	return fmt.Sprintf(`Mnemonic:   %s
Address:    %s
Public Key: %s
Secret Key: unencrypted:%s`, w.Mnemonic, w.Address, w.Pk, w.Sk)
}

func newVanity(matches MatchFunc, vanity VanityFunc) (Wallet, error) {
	ctx, cancel := context.WithCancel(context.Background())
	sigterm := make(chan os.Signal)
	signal.Notify(sigterm, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigterm
		cancel()
	}()
	count := make(chan struct{}, 0xff)
	match := make(chan Wallet)
	errs := make(chan error)
	i := 0
	for ; i < runtime.NumCPU(); i++ {
		go vanity(ctx, matches, match, count, errs)
	}
	fmt.Fprintf(os.Stderr, "\rRunning %d routines...\n", i)
	total := 0
	for {
		select {
		case <-ctx.Done():
			return Wallet{}, fmt.Errorf("context cancelled")
		case <-count:
			total += 1
			if (total % 111) == 0 {
				fmt.Fprintf(os.Stderr, "\r%d", total)
			}
		case err := <-errs:
			cancel()
			return Wallet{}, err
		case w := <-match:
			cancel()
			fmt.Fprintln(os.Stderr)
			return w, nil
		}
	}
}

func newVanityMnemonic(password string) VanityFunc {
	return func(ctx context.Context, matches MatchFunc, matchCh chan<- Wallet, countCh chan<- struct{}, errCh chan<- error) {
		var (
			mnemonic, addr string
			pub            ed25519.PublicKey
			priv           ed25519.PrivateKey
			err            error
		)
		for {
			select {
			case <-ctx.Done():
				break
			default:
				mnemonic, err = tzwallet.NewMnemonic()
				if err != nil {
					errCh <- err
					break
				} else if addr, pub, priv, err = tzwallet.KeysFromSeed(tzwallet.NewSeed(mnemonic, password)); err != nil {
					errCh <- err
					break
				} else if matches(addr[3:]) {
					matchCh <- Wallet{addr, mnemonic, tzwallet.PublicKeyFrom(pub), tzwallet.SecretKeyFrom(priv)}
					break
				}
				countCh <- struct{}{}
			}
		}
	}
}

func newVanityRand() VanityFunc {
	return func(ctx context.Context, matches MatchFunc, matchCh chan<- Wallet, countCh chan<- struct{}, errCh chan<- error) {
		seed := make([]byte, ed25519.SeedSize)
		for {
			_, err := rand.Read(seed)
			if err != nil {
				errCh <- err
				break
			} else if addr, pub, priv, err := tzwallet.KeysFromSeed(seed); err != nil {
				errCh <- err
				break
			} else if matches(addr[3:]) {
				matchCh <- Wallet{addr, "", tzwallet.PublicKeyFrom(pub), tzwallet.SecretKeyFrom(priv)}
			}
			countCh <- struct{}{}
		}
	}
}

func readPassword(s string) (string, error) {
	if s == "" {
		if terminal.IsTerminal(int(os.Stdout.Fd())) == false {
			return "", errors.New("password prompt requires terminal")
		}
		fmt.Print("Password: ")
		b, err := terminal.ReadPassword(int(syscall.Stdin))
		fmt.Println()
		return string(b), err
	}
	f, err := os.Open(s)
	if err != nil {
		return "", err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		s = scanner.Text()
	}
	if scanner.Scan() {
		err = errors.New("password file contains more than 1 line")
	}
	return s, err
}

func isValidArg(s string, isPrefix bool) bool {
	i := 0
	if isPrefix && len(s) > 0 {
		if strings.Contains(VALID_FIRST_CHARS, string(s[i])) == false {
			return false
		}
		i = 1
	}
	for ; i < len(s); i++ {
		if strings.Contains(VALID_CHARS, string(s[i])) == false {
			return false
		}
	}
	return true
}

func checkErr(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func cmdVanity(args ...string) {
	f := flag.NewFlagSet("vanity", flag.ExitOnError)
	prefix := f.String("prefix", "", "Prefix to find, `tz1{prefix}...`")
	suffix := f.String("suffix", "", "Suffix to find, `tz1...{suffix}`")
	re := f.String("regex", "", "Regex to match against, `tz1...{regex}...`. Caution, not validation of input")
	checkErr(f.Parse(args))

	if isValidArg(*prefix, true) == false || isValidArg(*suffix, false) == false {
		err := fmt.Errorf(`Invalid character(s) args: %s
First character of prefix must be one of: '%s'
Remaining characters must be one of: '%s'`, *prefix+*suffix, VALID_FIRST_CHARS, VALID_CHARS)
		checkErr(err)
	}

	var matches MatchFunc
	if *re != "" {
		if *prefix != "" || *suffix != "" {
			checkErr(errors.New("prefix and/or suffix cannot be supplid with regex"))
		}
		exp, err := regexp.Compile(*re)
		checkErr(err)
		matches = exp.MatchString
	} else if *prefix != "" && *suffix != "" {
		matches = func(addr string) bool {
			return strings.HasPrefix(addr, *prefix) && strings.HasSuffix(addr, *suffix)
		}
	} else if *prefix != "" {
		matches = func(addr string) bool { return strings.HasPrefix(addr, *prefix) }
	} else if *suffix != "" {
		matches = func(addr string) bool { return strings.HasSuffix(addr, *suffix) }
	} else {
		checkErr(errors.New("Missing 'prefix', 'suffix' or 'regex' argument"))
	}

	w, err := newVanity(matches, newVanityRand())
	checkErr(err)
	fmt.Println(w)
}

func cmdNew(args ...string) {
	f := flag.NewFlagSet("new", flag.ExitOnError)
	mnemonic := f.String("mnemonic", "", "BIP39 mnemonic phrase")
	password := f.String("password", "", "File containing password")
	checkErr(f.Parse(args))

	if *mnemonic == "" {
		m, err := tzwallet.NewMnemonic()
		checkErr(err)
		*mnemonic = m
	} else {
		words := strings.Split(*mnemonic, " ")
		if len(words) < 15 {
			checkErr(errors.New("Invalid mnemonic, requires BIP39 phrase"))
		}
	}

	p, err := readPassword(*password)
	checkErr(err)

	w, err := tzwallet.NewFromMnemonicAndPassword(*mnemonic, string(p))
	checkErr(err)
	fmt.Println(w)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Missing command")
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "new":
		cmdNew(os.Args[2:]...)
	case "vanity":
		cmdVanity(os.Args[2:]...)
	case "version":
		cmd.Version()
	default:
		fmt.Fprintln(os.Stderr, "Invalid command")
		usage()
		os.Exit(1)
	}
}
