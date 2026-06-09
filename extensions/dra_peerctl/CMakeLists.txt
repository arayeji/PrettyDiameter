PROJECT("DRA peer control API" C)
FD_ADD_EXTENSION(dra_peerctl dra_peerctl.c)

INSTALL(TARGETS dra_peerctl
	LIBRARY DESTINATION ${INSTALL_EXTENSIONS_SUFFIX}
	COMPONENT freeDiameter-dra-tools)
