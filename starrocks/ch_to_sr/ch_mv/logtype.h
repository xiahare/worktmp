static inline int devlogtype_encode(int devtype, int logtype)
{
    return (devtype*1000 + logtype);
}
 
typedef enum {
    LOGDEV_UNKNOWN = -1, /* Force cast to int */
    LOGDEV_FGT = 0, /* 0 */
    LOGDEV_FMG,     /* 1 */
    LOGDEV_SYS,     /* 2 */
    LOGDEV_FCT,     /* 3 */
    LOGDEV_FML,     /* 4 */
    LOGDEV_FWB,     /* 5 */
    LOGDEV_FCH,     /* 6 */
    LOGDEV_FAZ,     /* 7 */
    LOGDEV_CSCO,    /* 8 */
    LOGDEV_VULN,    /* 9 */
    LOGDEV_FSA,     /* 10 */
    LOGDEV_FDD,     /* 11 */
    LOGDEV_FAC,     /* 12 */
    LOGDEV_SELF,    /* 13 */
    LOGDEV_SNIFFER, /* 14 */
    LOGDEV_FPX,     /* 15 */
    LOGDEV_FSF,     /* 16 */ /* Fabric, not real device type */
    LOGDEV_FNA,     /* 17 */
    LOGDEV_SIEM,    /* 18 */ /* FAZ SIEM, not a real device type */
    LOGDEV_FDC,     /* 19 */
    LOGDEV_FAD,     /* 20 */
    LOGDEV_FFW,     /* 21 */
    LOGDEV_FAI,     /* 22 */
    LOGDEV_FSR,     /* 23 */
    LOGDEV_FIS,     /* 24 */
    LOGDEV_FED,     /* 25 */
    LOGDEV_FPA,     /* 26 */
    LOGDEV_FCA,     /* 27 */
    LOGDEV_FTC,     /* 28 */
    LOGDEV_FRA,     /* 29 */
    LOGDEV_FAP,     /* 30 */
    LOGDEV_ALL,     /* 31 */
    LOGDEV_sz,      /* 32 */
    LOGDEV_MAX = LOGDEV_sz
} LogDevType;
 
 
typedef enum {
  LOGTYPE_START         = 0,
  LOGTYPE_APPCTRL       = LOGTYPE_START,
  LOGTYPE_ATTACK        = 1,
  LOGTYPE_CONTENT       = 2,
  LOGTYPE_DLP           = 3,
  LOGTYPE_EMAILFILTER   = 4,
  LOGTYPE_EVENT         = 5,
  LOGTYPE_GENERIC       = 6,
  LOGTYPE_HISTORY       = 7,
  LOGTYPE_IM            = 8,
  LOGTYPE_SNIFFER       = 9,
  LOGTYPE_TRAFFIC       =10,
  LOGTYPE_VIRUS         =11,
  LOGTYPE_VOIP          =12,
  LOGTYPE_WEBFILTER     =13,
  LOGTYPE_NETSCAN       =14,
  LOGTYPE_EVENT_EX      =15,  /* extended log type - FGT fct event log */
  LOGTYPE_TRAFFIC_EX    =16,  /* extended log type - FGT fct traffic log */
  LOGTYPE_NETSCAN_EX    =17,  /* extended log type - FGT fct vuln log */
  LOGTYPE_WAF           =18,
  LOGTYPE_GTP           =19,
  LOGTYPE_DNS           =20,
  LOGTYPE_SSH           =21,
  LOGTYPE_SSL           =22,
  LOGTYPE_FFLT          =23,
  LOGTYPE_ASSET         =24,
  LOGTYPE_PROTOCOL      =25,
  LOGTYPE_SIEM          =26,  /* FAZ SIEM all-in-one log type */
  LOGTYPE_ZTNA          =27,
  LOGTYPE_SECURITY      =28,
  LOGTYPE_MAX           =29,  /* end of "real" log types */
 
  /* log type extension */
  LOGTYPE_EXT_START       = 32,
  LOGTYPE_EXT_PBD         = LOGTYPE_EXT_START, /* used in one summary FV to use
                                                  current filter framework */
  LOGTYPE_EXT_LOCAL_EVENT = 33,                /* local event log in root adom */
 
  LOGTYPE_EXT_MAX,            /* LOGTYPE_EXT_MAX should not exceed 64 due to
                                 the uint64_t ltype_masks restriction */
 
  LOGTYPE_ANYTYPE         = 65535,
} logtype_t;