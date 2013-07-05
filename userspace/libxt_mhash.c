#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <xtables.h>
#include <linux/netfilter/xt_mhash.h>

static const struct option xt_mhash_opts[] = {
    {"mvalue", 1, NULL, '1'},
    {NULL,NULL,NULL,NULL},
};

static void mhash_help(void)
{
    printf("mhash v%s options:\n"
    "--mvalue value\t\tvalue must between 0 - 5\n"
    "\nExample:\n"
    "iptables -t mangle -A PREROUTING -m mhash --mvalue 1 -j MARK --set-mark 1\n"
    , MHASH_VERSION);
}

static int mhash_parse(int c, char** argv,int invert, unsigned int *flags,
                const void *entry, struct xt_entry_match **match)
{
    struct xt_mhash_info *info = (struct xt_mhash_info *)(*match)->data;

    switch(c) {
        case '1':
            info->mvalue = atoi(optarg);
            if(*flags || info->mvalue >= BUCKET_SIZE)
                xtables_error(PARAMETER_PROBLEM,"--mvalue must be set.\n");
            *flags = 1;
            return true;
    }

    return false;
}

static void mhash_final_check(unsigned int flags)
{
    if(flags == 0)
        xtables_error(PARAMETER_PROBLEM, "xt_mhash: You need to "
                                      "specify --mvalue\n");
}

static void mhash_print(const void *entry,
                        const struct xt_entry_match *match, int numeric)
{
    const struct xt_mhash_info *info = (const void *)match->data;
    printf("mhash value: %d  ",info->mvalue);
}

static void mhash_save(const void *entry, const struct xt_entry_match *match)
{
    const struct xt_mhash_info *info = (const void *)match->data;
    printf("mhash value: %d\n",info->mvalue);
}

static struct xtables_match mhash_mt_reg[] = {
    {
        .family     = NFPROTO_UNSPEC,
        .name       = "mhash",
        .revision   = 0,
        .version    = XTABLES_VERSION,
        .size       = XT_ALIGN(sizeof(struct xt_mhash_info)),
        .userspacesize = XT_ALIGN(sizeof(struct xt_mhash_info)),
        .help       = mhash_help,
        .parse      = mhash_parse,
        .final_check = mhash_final_check,
        .print      = mhash_print,
        .save       = mhash_save,
        .extra_opts = xt_mhash_opts,
    },
    {
        .name       = "mhash",
        .version    = XTABLES_VERSION,
        .family     = NFPROTO_UNSPEC,
        .revision   = 1,
        .size       = XT_ALIGN(sizeof(struct xt_mhash_info)),
        .userspacesize = XT_ALIGN(sizeof(struct xt_mhash_info)),
        .help       = mhash_help,
        .final_check = mhash_final_check,
        .parse      = mhash_parse,
        .print      = mhash_print,
        .save       = mhash_save,
        .extra_opts       = xt_mhash_opts,
    },
};

void _init(void)
{
    xtables_register_matches(mhash_mt_reg, ARRAY_SIZE(mhash_mt_reg));
}
