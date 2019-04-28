
include $(TOPDIR)/rules.mk

PKG_NAME:=lan-scan
PKG_VERSION:=1.0

PKG_BUILD_DIR:= $(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

define Package/lan-scan
	SECTION  := net
 	CATEGORY := Network
	TITLE    := lan attached device list 
	DEPENDS  := +libadapter
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)
endef

define Package/lan-scan/install
	$(INSTALL_DIR) $(1)/etc/init.d
	$(CP) ./files/lan-scan.init $(1)/etc/init.d/lan-scan
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/lan-scan $(1)/usr/sbin/
endef

$(eval $(call BuildPackage,lan-scan))
