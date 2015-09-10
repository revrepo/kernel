/*
 *
 *   RevSw TCP Sysctl Support
 *
 * This module provides the sysctls that the various RevSw
 * congestion control algortihms and session database require.
 *
 * Copyright (c) 2013-2014, Rev Software, Inc.
 * All Rights Reserved.
 * This code is confidential and proprietary to Rev Software, Inc
 * and may only be used under a license from Rev Software Inc.
 */

#ifndef __TCP_REVSW_LOGUTILS_H__
#define __TCP_REVSW_LOGUTILS_H__

#define TCP_REVSW_UTL_LOG_DEFAULT	0

#define TCP_REVSW_RBE_LOG_DEFAULT	TCP_REVSW_UTL_LOG_DEFAULT
#define TCP_REVSW_STD_LOG_DEFAULT	TCP_REVSW_UTL_LOG_DEFAULT

#define TCP_REVSW_UTL_LOG_NOLOG  TCP_REVSW_UTL_LOG_DEFAULT
#define TCP_REVSW_UTL_LOG_ERR  (TCP_REVSW_UTL_LOG_DEFAULT + 1)
#define TCP_REVSW_UTL_LOG_INFO  (TCP_REVSW_UTL_LOG_DEFAULT + 2)
#define TCP_REVSW_UTL_LOG_SACK  (TCP_REVSW_UTL_LOG_DEFAULT + 3)
#define TCP_REVSW_UTL_LOG_VERBOSE  (TCP_REVSW_UTL_LOG_DEFAULT + 4)

#define TCP_REVSW_SESS_LOG_DEFAULT	TCP_REVSW_UTL_LOG_DEFAULT


#define LOG_IT(qualifier, loglevel, format, ...)  { \
        if (qualifier && qualifier >= loglevel)  { \
                if (loglevel == TCP_REVSW_UTL_LOG_ERR)          \
                        pr_err(format, ## __VA_ARGS__);         \
                else                                            \
                        pr_info(format, ## __VA_ARGS__);        \
        }                                                       \
}



#endif
