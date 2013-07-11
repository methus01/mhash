#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>

#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/xt_mhash.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ji Huang <jesson.cd@gmail.com>");
MODULE_DESCRIPTION("Xtables: mhash match");
MODULE_ALIAS("ipt_mhash");

static bool mhash_mt(const struct sk_buff *skb, const struct xt_match_param *par)
{
    const struct xt_mhash_info *info = par->matchinfo;
    const struct iphdr *iph = ip_hdr(skb);
    //printk(KERN_INFO "xt_mhash: "
    //                "bucket size=%d, value=%d\n",
    //                info->hash_bucket,info->hash_value);

    if(abs(ntohl(iph->daddr) % BUCKET_SIZE) == info->mvalue) {
        return true;
    }
    return false;
}

static struct xt_match mhash_mt_reg __read_mostly = {
    .name       = "mhash",
    .revision   = 1,
    .family     = NFPROTO_UNSPEC,
    .match      = mhash_mt,
    .matchsize  = sizeof(struct xt_mhash_info),
    .me         = THIS_MODULE,
};

static int __init mhash_mt_init(void)
{
    printk(KERN_INFO "xt_mhash: init.\n");
    return xt_register_match(&mhash_mt_reg);
}

static void __exit mhash_mt_exit(void)
{
    printk(KERN_INFO "xt_mhash: exit.\n");
    xt_unregister_match(&mhash_mt_reg);
}

module_init(mhash_mt_init);
module_exit(mhash_mt_exit);
