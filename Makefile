DEBIAN_DIST=experimental
HSN2_COMPONENT=malicious-domains

PKG=hsn2-$(HSN2_COMPONENT)_$(HSN2_VER)-$(BUILD_NUMBER)_all
package: clean
	mkdir -p $(PKG)/opt/hsn2/malicious-domains
	mkdir -p $(PKG)/etc/hsn2/
	mkdir -p $(PKG)/etc/init.d
	mkdir -p $(PKG)/DEBIAN
	cp *.py $(PKG)/opt/hsn2/malicious-domains/
	cp -r verdict verifiers $(PKG)/opt/hsn2/malicious-domains/
	cp debian/initd $(PKG)/etc/init.d/hsn2-malicious-domains
	cp debian/malicious-domains.conf $(PKG)/etc/hsn2/malicious-domains.conf
	cp debian/malicious_list $(PKG)/opt/hsn2/malicious-domains/
	cp debian/control $(PKG)/DEBIAN
	cp debian/conffiles $(PKG)/DEBIAN
	sed -i "s/{VER}/${HSN2_VER}-${BUILD_NUMBER}/" $(PKG)/DEBIAN/control
	sed -i "s/{DEBIAN_DIST}/${DEBIAN_DIST}/" $(PKG)/DEBIAN/control
	fakeroot dpkg -b $(PKG)
	
clean:
	rm -rf $(PKG)