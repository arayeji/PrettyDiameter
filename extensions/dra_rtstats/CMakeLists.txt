PROJECT("DRA relay traffic statistics" C)
FD_ADD_EXTENSION(dra_rtstats dra_rtstats.c)

INSTALL(TARGETS dra_rtstats
	LIBRARY DESTINATION ${INSTALL_EXTENSIONS_SUFFIX}
	COMPONENT freeDiameter-dra-tools)
