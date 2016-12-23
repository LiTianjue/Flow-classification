#include "common.h"

int check_polic_ready()
{
	int ret = 0;
	GLOBAL_LOCK(g_info);
	ret = g_info->isset && g_info->updata_flag;
	GLOBAL_UNLOCK(g_info);

	return ret;
}

int get_polic(char *out)
{
	int ret = 0;
	GLOBAL_LOCK(g_info);
	strcpy(out,g_info->bpf);
	GLOBAL_UNLOCK(g_info);

	if(strlen(out) < 4)
		ret = -1;
	return ret;
}
