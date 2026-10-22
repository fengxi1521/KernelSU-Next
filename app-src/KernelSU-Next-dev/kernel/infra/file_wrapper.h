#ifndef XFG_FILE_WRAPPER_H
#define XFG_FILE_WRAPPER_H

#include <linux/file.h>
#include <linux/fs.h>

int xfg_install_file_wrapper(int fd);
void xfg_file_wrapper_init(void);

#endif // XFG_FILE_WRAPPER_H
