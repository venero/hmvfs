//#define TEST 1

//#define HMFS_SUPER_MAGIC 0xABBF //this should be defined at **uapi/linux/magic.h**



#ifdef TEST
void printtty(const char *format, ...);
#define print printtty 		//print to TTY for debugging convience
#define tprint printtty 	//test print
#else
#define print printk
#define tprint
#endif



