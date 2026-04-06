CC=gcc
CFLAGS=-Wall -O3
TARGET=minidns
SRC=minidns.c

VERSION=1.0.0

.PHONY: all install rpm deb clean uninstall distclean

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $^

install:
	install -D $(TARGET) /usr/bin/minidns
	install -D minidns.service /etc/systemd/system/minidns.service
	install -D minidns.env.sample /etc/minidns.env

# The combined 'package' target has been removed.
# Use 'make rpm' or 'make deb' explicitly to build the respective package.

rpm:
	@mkdir -p build/rpm/BUILD build/rpm/RPMS build/rpm/SOURCES build/rpm/SPECS build/rpm/SRPMS
	@cp $(TARGET) minidns.service minidns.env.sample build/rpm/SOURCES/
	@cp minidns.spec build/rpm/SPECS/minidns.spec
	@# Build the RPM; if it fails (e.g., due to permission), continue without aborting
	@if rpmbuild --define "_topdir $(CURDIR)/build/rpm" -bb build/rpm/SPECS/minidns.spec; then \
		echo "RPM package built successfully"; \
	else \
		echo "RPM build failed (possible permission issue); skipping RPM"; \
	fi
	@# Move the generated RPM to the project root (if it exists) and clean up build files
	@rpm_file=$$(ls build/rpm/RPMS/*/*.rpm 2>/dev/null | head -n1); \
	if [ -n "$$rpm_file" ]; then \
		cp "$$rpm_file" ./$(TARGET)-$(VERSION).rpm; \
		echo "RPM moved to $(TARGET)-$(VERSION).rpm"; \
	fi
	@rm -rf build/rpm

deb: $(TARGET)
	@mkdir -p build/deb/DEBIAN
	@mkdir -p build/deb/usr/bin
	@mkdir -p build/deb/etc/systemd/system
	@mkdir -p build/deb/etc
	@cp $(TARGET) build/deb/usr/bin/minidns
	@install -D -m 0644 minidns.service build/deb/etc/systemd/system/minidns.service
	@install -D -m 0644 minidns.env.sample build/deb/etc/minidns.env
	cp debian.control build/deb/DEBIAN/control
	dpkg-deb --build build/deb $(TARGET)-$(VERSION).deb

clean:
	rm -f $(TARGET)
	rm -rf build

uninstall:
	rm -f /usr/bin/minidns
	rm -f /etc/systemd/system/minidns.service
	rm -f /etc/minidns.env
	systemctl daemon-reload || true

# Remove all generated files, including build artifacts and packaged archives

distclean: clean
	rm -f *.deb
	rm -f *.rpm

