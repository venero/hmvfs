
static bst_node_t *__construct_segno_tree(struct hmfs_sb_info *sbi, int st_i, 
				int ed_i, uint64_t *size)
{
	bst_node_t *node = NULL, *left, *right;
	int mid;
	uint64_t val;

	if (st_i == ed_i - 1) {
		struct hmfs_dev_info *dev_i = DEV_INFO(sbi, st_i);
		
		if (dev_i->initsize) {
			*size += (dev_i->end_ofs - dev_i->main_ofs) >> SM_I(sbi)->segment_size;
			node = kzalloc(sizeof(bst_node_t), GFP_KERNEL);
			node->val = st_i;
			return node;
		}
		return NULL;
	}

	mid = (st_i + ed_i) / 2;
	left = __construct_segno_tree(sbi, st_i, mid, size);
	val = *size;
	right = __construct_segno_tree(sbi, mid, ed_i, size);

	if (left && right) {
		node = kzalloc(sizeof(bst_node_t), GFP_KERNEL);
		node->val = val;
		node->right = right;
		node->left = left;
	} else if (left)
		node = left;
	else if (right)
		node = right;
	return node;
}

inline bst_node_t *construct_segno_tree(struct hmfs_sb_info *sbi)
{
	uint64_t size = 0;
	bst_node_t *root;

	BUILD_BUG_ON((NR_DEVICE - 1) & NR_DEVICE);
	root = __construct_segno_tree(sbi, 0, NR_DEVICE, &size);
	return root;
}

static int __query_device_index(bst_node_t *node, uint64_t segno)
{
	if (node->left == node->right)
		return node->val;
	else if (segno < node->val)
		return __query_device_index(node->left, segno);
	return __query_device_index(node->right, segno);
	
}

inline int query_device_index(struct hmfs_sb_info *sbi, uint64_t segno)
{
	return __query_device_index(sbi->device_root, segno);	
}


