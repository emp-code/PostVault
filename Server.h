#ifndef PV_SERVER_H
#define PV_SERVER_H

void pv_setUser(const uid_t new_uid, const gid_t new_gid);
int pv_init();
void respondClient(const int sock);

#endif
