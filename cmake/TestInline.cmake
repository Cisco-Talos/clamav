# From https://gitlab.kitware.com/cmake/community/-/wikis/contrib/macros/TestInline
# Modified to use configure_file() approach, and to address script path issues.
# See: https://stackoverflow.com/questions/3781222/add-definitions-vs-configure-file
# Inspired from /usr/share/autoconf/autoconf/c.m4

GET_FILENAME_COMPONENT(_selfdir_TestInline
	 "${CMAKE_CURRENT_LIST_FILE}" PATH)

FOREACH(KEYWORD "inline" "__inline__" "__inline")
   IF(NOT DEFINED C_INLINE)
     TRY_COMPILE(C_HAS_${KEYWORD} "${CMAKE_CURRENT_BINARY_DIR}"
       "${_selfdir_TestInline}/TestInline.c"
       COMPILE_DEFINITIONS "-Dinline=${KEYWORD}")
     IF(C_HAS_${KEYWORD})
       SET(C_INLINE TRUE)
       SET(INLINE_KEYWORD "${KEYWORD}" CACHE INTERNAL "inline macro defined as ${KEYWORD}")
     ENDIF(C_HAS_${KEYWORD})
   ENDIF(NOT DEFINED C_INLINE)
ENDFOREACH(KEYWORD)
IF(NOT DEFINED C_INLINE)
   SET(INLINE_KEYWORD "" CACHE INTERNAL "inline macro definition not required")
ENDIF(NOT DEFINED C_INLINE)
