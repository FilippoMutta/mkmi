/*
   File: include/mkmi/mkmi_version.hpp

   MKMI version struct
*/

#pragma once
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct MKMI_VersionInfo {
	uint16_t Major;      /* Major version: API incompatibility */
	uint16_t Minor;      /* Minor version: ABI incompatibility */
	uint16_t Feature;    /* Feature version: New feature or major bugfix */
	uint16_t Patch;      /* Patch version: Minor bugfix */
};

extern const MKMI_VersionInfo MKMI_CurrentVersion;

#ifdef __cplusplus
}
#endif
