# tzwallet
#

VERSION = '0.0.1'
TIME    = $(shell date '+%A %b %Y %X')
COMMIT  = $(shell git rev-parse --short=10 HEAD)
REPO    = "github.com/juztin/tzwallet"


LDFLAG_COMMIT_EXPERIMENTAL = -X "github.com/juztin/tzwallet/cmd.Commit=$(COMMIT) - experimental"
LDFLAG_COMMIT              = -X "github.com/juztin/tzwallet/cmd.Commit=$(COMMIT)"
LDFLAG_BUILT               = -X "github.com/juztin/tzwallet/cmd.Built=$(TIME)"
LDFLAG_VERSION             = -X "github.com/juztin/tzwallet/cmd.CLIVersion=$(VERSION)"
LDFLAGS_EXPERIMENTAL       = '$(LDFLAG_COMMIT_EXPERIMENTAL) $(LDFLAG_BUILT) $(LDFLAG_VERSION)'
LDFLAGS_DIST               = '$(LDFLAG_COMMIT)  $(LDFLAG_BUILT) $(LDFLAG_VERSION)'


.PHONY: generate cli dist


print-%: ; @echo '$(subst ','\'',$*=$($*))'

all: cli

cli:
	@mkdir -p ./build
	# Building tzwallet...
	@go build -v -ldflags=$(LDFLAGS_EXPERIMENTAL) -o build/tzwallet ./cmd/tzwallet

dist: generate
	@mkdir -p ./dist
	# Building Linux...
	@GOOS=linux   GOARCH=amd64 go build -ldflags=$(LDFLAGS_DIST) -o dist/tzwallet_linux_amd64   github.com/juztin/tzwallet/cmd/tzwallet
	# Building Mac...
	@GOOS=darwin  GOARCH=amd64 go build -ldflags=$(LDFLAGS_DIST) -o dist/tzwallet_darwin_amd64  github.com/juztin/tzwallet/cmd/tzwallet
	# Building Windows...
	@GOOS=windows GOARCH=amd64 go build -ldflags=$(LDFLAGS_DIST) -o dist/tzwallet_windows_amd64 github.com/juztin/tzwallet/cmd/tzwallet

clean:
	@rm -f ./bin/*
	@rm -f ./dist/*
