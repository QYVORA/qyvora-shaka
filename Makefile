# SHAKA Makefile

BINARY ?= shaka
PREFIX ?= /usr/local
DESTDIR ?=

VERSION ?= dev
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
USER    ?= $(shell id -u -n)

LDFLAGS := -s -w \
	-X github.com/QYVORA/qyvora-shaka/internal/version.Version=$(VERSION) \
	-X github.com/QYVORA/qyvora-shaka/internal/version.Commit=$(COMMIT) \
	-X github.com/QYVORA/qyvora-shaka/internal/version.Date=$(DATE) \
	-X github.com/QYVORA/qyvora-shaka/internal/version.BuildUser=$(USER)

# --- install layout ------------------------------------------------------
# System-wide install (default PREFIX=/usr/local, typically needs root):
#   /usr/local/bin/shaka                         command
#   /usr/local/share/applications/shaka.desktop  desktop entry
#   /usr/local/share/icons/hicolor/512x512/apps/shaka.png
#   /usr/local/share/pixmaps/shaka.png
# User install (make install-user) mirrors the same layout under ~/.local.

ICON    := assets/shaka.png
DESKTOP := assets/shaka.desktop

BINDIR    := $(DESTDIR)$(PREFIX)/bin
ICONDIR   := $(DESTDIR)$(PREFIX)/share/icons/hicolor/512x512/apps
PIXMAPDIR := $(DESTDIR)$(PREFIX)/share/pixmaps
APPDIR    := $(DESTDIR)$(PREFIX)/share/applications

USERBIN    := $(HOME)/.local/bin
USERICON   := $(HOME)/.local/share/icons/hicolor/512x512/apps
USERPIXMAP := $(HOME)/.local/share/pixmaps
USERAPP    := $(HOME)/.local/share/applications

.PHONY: all build test test-race vet fmt check install install-user uninstall uninstall-user clean

all: build

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./cmd/shaka

test:
	go test ./... -count=1 -timeout 60s

test-race:
	go test -race ./... -count=1 -timeout 120s

vet:
	go vet ./...

fmt:
	gofmt -w cmd internal pkg

check: fmt vet test

install: build
	install -d $(BINDIR)
	install -m 0755 bin/$(BINARY) $(BINDIR)/$(BINARY)
	$(MAKE) install-data

install-data:
	install -d $(ICONDIR) $(PIXMAPDIR) $(APPDIR)
	install -m 0644 $(ICON) $(ICONDIR)/shaka.png
	install -m 0644 $(ICON) $(PIXMAPDIR)/shaka.png
	sed -e 's|@PREFIX@|$(PREFIX)|g' $(DESKTOP) > $(APPDIR)/shaka.desktop
	chmod 0644 $(APPDIR)/shaka.desktop
	update-desktop-database $(APPDIR) 2>/dev/null || true
	gtk-update-icon-cache -f $(DESTDIR)$(PREFIX)/share/icons/hicolor 2>/dev/null || true
	@echo "shaka installed to $(BINDIR) with icon and desktop entry."

install-user: build
	install -d $(USERBIN)
	install -m 0755 bin/$(BINARY) $(USERBIN)/$(BINARY)
	install -d $(USERICON) $(USERPIXMAP) $(USERAPP)
	install -m 0644 $(ICON) $(USERICON)/shaka.png
	install -m 0644 $(ICON) $(USERPIXMAP)/shaka.png
	sed -e 's|@PREFIX@|$(HOME)/.local|g' $(DESKTOP) > $(USERAPP)/shaka.desktop
	chmod 0644 $(USERAPP)/shaka.desktop
	update-desktop-database $(USERAPP) 2>/dev/null || true
	gtk-update-icon-cache -f $(HOME)/.local/share/icons/hicolor 2>/dev/null || true
	@echo "shaka installed to $(USERBIN) with icon and desktop entry."
	@echo "Add $$HOME/.local/bin to your PATH if it is not already there."

uninstall:
	rm -f $(BINDIR)/$(BINARY)
	rm -f $(ICONDIR)/shaka.png $(PIXMAPDIR)/shaka.png $(APPDIR)/shaka.desktop
	update-desktop-database $(APPDIR) 2>/dev/null || true
	gtk-update-icon-cache -f $(DESTDIR)$(PREFIX)/share/icons/hicolor 2>/dev/null || true

uninstall-user:
	rm -f $(USERBIN)/$(BINARY)
	rm -f $(USERICON)/shaka.png $(USERPIXMAP)/shaka.png $(USERAPP)/shaka.desktop
	update-desktop-database $(USERAPP) 2>/dev/null || true
	gtk-update-icon-cache -f $(HOME)/.local/share/icons/hicolor 2>/dev/null || true

clean:
	rm -rf bin
