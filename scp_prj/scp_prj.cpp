#include "Header.h"
using namespace std;
/*static guint8 message_type = 0;
static guint dlr = 0;
static guint slr = 0; */

static sccp_assoc_info_t *assoc;

static sccp_assoc_info_t  no_assoc = { 0,0,0,0,0,FALSE,FALSE,NULL,NULL,SCCP_PLOAD_NONE,NULL,NULL,NULL,0 };

static int proto_sccp = -1;
static int hf_sccp_message_type = -1;
static int hf_sccp_variable_pointer1 = -1;
static int hf_sccp_variable_pointer2 = -1;
static int hf_sccp_variable_pointer3 = -1;
static int hf_sccp_optional_pointer = -1;
static int hf_sccp_param_length = -1;
static int hf_sccp_ssn = -1;
static int hf_sccp_gt_digits = -1;
static reassembly_table sccp_xudt_msg_reassembly_table;


/*static void
get_hfi_length(header_field_info *hfinfo, tvbuff_t *tvb, const gint start, gint *length,
gint *item_length); */





guint
tvb_offset_from_real_beginning_counter(const tvbuff_t *tvb, const guint counter)
{
	//if (tvb-> ops->tvb_offset)
	//return tvb->ops->tvb_offset(tvb, counter);

	DISSECTOR_ASSERT_NOT_REACHED();
	return 0;
}


guint
tvb_offset_from_real_beginning(const tvbuff_t *tvb)
{
	return tvb_offset_from_real_beginning_counter(tvb, 0);
}


gint
tvb_raw_offset(tvbuff_t *tvb)
{
	return ((tvb->raw_offset == -1) ? (tvb->raw_offset = tvb_offset_from_real_beginning(tvb)) : tvb->raw_offset);
}

struct tvbuff *
	tvb_get_ds_tvb(tvbuff_t *tvb)
{
	return(tvb->ds_tvb);
}

static field_info *
new_field_info(proto_tree *tree, header_field_info *hfinfo, tvbuff_t *tvb,
	const gint start, const gint item_length)
{
	field_info *fi = NULL;

	//FIELD_INFO_NEW(fi);

	fi->hfinfo = hfinfo;
	fi->start = start;
	fi->start += (tvb) ? tvb_raw_offset(tvb) : 0;
	fi->length = item_length;
	fi->tree_type = -1;
	fi->flags = 0;
	/*	if (!PTREE_DATA(tree)->visible)
	FI_SET_FLAG(fi, FI_HIDDEN);
	fvalue_init(&fi->value, fi->hfinfo->type);
	fi->rep = NULL; */

	/* add the data source tvbuff */
	fi->ds_tvb = tvb ? tvb_get_ds_tvb(tvb) : NULL;

	fi->appendix_start = 0;
	fi->appendix_length = 0;

	return fi;
}


static field_info *
alloc_field_info(proto_tree *tree, header_field_info *hfinfo, tvbuff_t *tvb,
	const gint start, gint *length);


static void
get_hfi_length(header_field_info *hfinfo, tvbuff_t *tvb, const gint start, gint *length,
	gint *item_length);


static int
compute_offset_and_remaining(const tvbuff_t *tvb, const gint offset, guint *offset_ptr, guint *rem_len)
{
	int exception = FragmentBoundsError;

	//exception = compute_offset(tvb, offset, offset_ptr);
	//if (!exception)
	//	*rem_len = tvb->length - *offset_ptr;

	return exception;
}

gint
tvb_length_remaining(const tvbuff_t *tvb, const gint offset)
{
	guint abs_offset, rem_length;
	int exception;

	DISSECTOR_ASSERT(tvb && tvb->initialized);

	exception = compute_offset_and_remaining(tvb, offset, &abs_offset, &rem_length);
	if (exception)
		return -1;

	return rem_length;
}


static void
get_hfi_length(header_field_info *hfinfo, tvbuff_t *tvb, const gint start, gint *length,
	gint *item_length)
{
	gint length_remaining;

	/*
	* We only allow a null tvbuff if the item has a zero length,
	* i.e. if there's no data backing it.
	*/
	DISSECTOR_ASSERT(tvb != NULL || *length == 0);

	/*
	* XXX - in some protocols, there are 32-bit unsigned length
	* fields, so lengths in protocol tree and tvbuff routines
	* should really be unsigned.  We should have, for those
	* field types for which "to the end of the tvbuff" makes sense,
	* additional routines that take no length argument and
	* add fields that run to the end of the tvbuff.
	*/
	if (*length == -1) {
		/*
		* For FT_NONE, FT_PROTOCOL, FT_BYTES, and FT_STRING fields,
		* a length of -1 means "set the length to what remains in
		* the tvbuff".
		*
		* The assumption is either that
		*
		*	1) the length of the item can only be determined
		*	   by dissection (typically true of items with
		*	   subitems, which are probably FT_NONE or
		*	   FT_PROTOCOL)
		*
		* or
		*
		*	2) if the tvbuff is "short" (either due to a short
		*	   snapshot length or due to lack of reassembly of
		*	   fragments/segments/whatever), we want to display
		*	   what's available in the field (probably FT_BYTES
		*	   or FT_STRING) and then throw an exception later
		*
		* or
		*
		*	3) the field is defined to be "what's left in the
		*	   packet"
		*
		* so we set the length to what remains in the tvbuff so
		* that, if we throw an exception while dissecting, it
		* has what is probably the right value.
		*
		* For FT_STRINGZ, it means "the string is null-terminated,
		* not null-padded; set the length to the actual length
		* of the string", and if the tvbuff if short, we just
		* throw an exception.
		*
		* It's not valid for any other type of field.
		*/
		/*	switch (hfinfo->type) {

		case FT_PROTOCOL:

		// We allow this to be zero-length - for
		// example, an ONC RPC NULL procedure has
		// neither arguments nor reply, so the
		// payload for that protocol is empty.

		// However, if the length is negative, the
		// start offset is *past* the byte past the
		// end of the tvbuff, so we throw an
		// exception.

		*length = tvb_length_remaining(tvb, start);
		if (*length < 0) {

		// Use "tvb_ensure_bytes_exist()"
		// to force the appropriate exception
		// to be thrown.
		//
		tvb_ensure_bytes_exist(tvb, start, 0);
		}
		DISSECTOR_ASSERT(*length >= 0);
		break;

		case FT_NONE:
		case FT_BYTES:
		case FT_STRING:
		*length = tvb_ensure_length_remaining(tvb, start);
		DISSECTOR_ASSERT(*length >= 0);
		break;

		case FT_STRINGZ:

		// Leave the length as -1, so our caller knows
		// it was -1.

		break;

		default:
		DISSECTOR_ASSERT_NOT_REACHED();
		} */
		*item_length = *length;
	}
	else {
		*item_length = *length;
		if (hfinfo->type == FT_PROTOCOL || hfinfo->type == FT_NONE) {

			// These types are for interior nodes of the
			// tree, and don't have data associated with
			// them; if the length is negative (XXX - see
			// above) or goes past the end of the tvbuff,
			// cut it short at the end of the tvbuff.
			// That way, if this field is selected in
			//Wireshark, we don't highlight stuff past
			// the end of the data.

			// XXX - what to do, if we don't have a tvb? 
			if (tvb) {
				length_remaining = tvb_length_remaining(tvb, start);
				if (*item_length < 0 ||
					(*item_length > 0 &&
					(length_remaining < *item_length)))
					*item_length = length_remaining;
			}
		}
		if (*item_length < 0) {
			THROW(ReportedBoundsError);
		}
	}
}




static field_info *
alloc_field_info(proto_tree *tree, header_field_info *hfinfo, tvbuff_t *tvb, const gint start,
	gint *length)
{
	gint		   item_length;

	get_hfi_length(hfinfo, tvb, start, length, &item_length);
	return new_field_info(tree, hfinfo, tvb, start, item_length);
}



/* special-case header field used within proto.c */
/* static header_field_info hfi_text_only =
{ "Text item",	"text", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };
int hf_text_only = -1; */


/* Add a field_info struct to the proto_tree, encapsulating it in a proto_node */
static proto_item *
proto_tree_add_node(proto_tree *tree, field_info *fi)
{
	proto_node *pnode = NULL, *tnode, *sibling;
	field_info *tfi;

	/*

	//Make sure "tree" is ready to have subtrees under it, by
	//checking whether it's been given an ett_ value.

	// "PNODE_FINFO(tnode)" may be null; that's the case for the root
	// node of the protocol tree.  That node is not displayed,
	// so it doesn't need an ett_ value to remember whether it
	// was expanded.

	tnode = tree;
	// tfi = PNODE_FINFO(tnode);
	//if (tfi != NULL && (tfi->tree_type < 0 || tfi->tree_type >= num_tree_types)) {
	//	REPORT_DISSECTOR_BUG(ep_strdup_printf("\"%s\" - \"%s\" tfi->tree_type: %u invalid (%s:%u)",
	//	fi->hfinfo->name, fi->hfinfo->abbrev, tfi->tree_type, __FILE__, __LINE__));
	// XXX - is it safe to continue here?
	}

	PROTO_NODE_NEW(pnode);
	pnode->parent = tnode;
	PNODE_FINFO(pnode) = fi;
	pnode->tree_data = PTREE_DATA(tree);

	if (tnode->last_child != NULL) {
	sibling = tnode->last_child;
	DISSECTOR_ASSERT(sibling->next == NULL);
	sibling->next = pnode;
	}
	else
	tnode->first_child = pnode;
	tnode->last_child = pnode;

	tree_data_add_maybe_interesting_field(pnode->tree_data, fi);
	*/
	return (proto_item *)pnode;
}

static proto_item *
proto_tree_add_text_node(proto_tree *tree, tvbuff_t *tvb, gint start, gint length);

static proto_item *
proto_tree_add_pi(proto_tree *tree, header_field_info *hfinfo, tvbuff_t *tvb, gint start,
	gint *length)
{
	proto_item *pi;
	field_info *fi;

	fi = alloc_field_info(tree, hfinfo, tvb, start, length);
	pi = proto_tree_add_node(tree, fi);

	return pi;
}

// Add FT_UINT{8,16,24,32} to a proto_tree 
proto_item *
proto_tree_add_uint(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
	gint length, guint32 value)
{
	proto_item	  *pi = NULL;
	header_field_info *hfinfo = (header_field_info *)malloc(sizeof(header_field_info *));

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	switch (hfinfo->type) {
	case FT_UINT8:
	case FT_UINT16:
	case FT_UINT24:
	case FT_UINT32:
	case FT_FRAMENUM:
		//pi = proto_tree_add_pi(tree, hfinfo, tvb, start, &length);
		//proto_tree_set_uint(PNODE_FINFO(pi), value);
		break;

	default:
		DISSECTOR_ASSERT_NOT_REACHED();
	}

	return pi;
}

/* Add a text-only node, leaving it to our caller to fill the text in */
static proto_item *
proto_tree_add_text_node(proto_tree *tree, tvbuff_t *tvb, gint start, gint length)
{
	proto_item *pi = NULL;

	if (tree == NULL)
		return NULL;

	//pi = proto_tree_add_pi(tree, &hfi_text_only, tvb, start, &length);

	return pi;
}


/* Add a text-only node to the proto_tree */
proto_item *
proto_tree_add_text(proto_tree *tree, tvbuff_t *tvb, gint start, gint length,
	const char *format, ...)
{
	proto_item	  *pi;
	va_list		   ap;
	//header_field_info *hfinfo;

	//TRY_TO_FAKE_THIS_ITEM(tree, hf_text_only, hfinfo);

	pi = proto_tree_add_text_node(tree, tvb, start, length);

	//TRY_TO_FAKE_THIS_REPR(pi);

	//va_start(ap, format);
	//proto_tree_set_representation(pi, format, ap);
	va_end(ap);

	return pi;
}

static int
compute_offset(const tvbuff_t *tvb, const gint offset, guint *offset_ptr)
{
	int exception;

	if (offset >= 0) {
		/* Positive offset - relative to the beginning of the packet. */
		if ((guint)offset > tvb->reported_length) {
			if (tvb->flags & TVBUFF_FRAGMENT) {
				exception = FragmentBoundsError;
			}
			else {
				exception = ReportedBoundsError;
			}
			return exception;
		}
		else if ((guint)offset > tvb->length) {
			return BoundsError;
		}
		else {
			*offset_ptr = offset;
		}
	}
	else {
		/* Negative offset - relative to the end of the packet. */
		if ((guint)-offset > tvb->reported_length) {
			if (tvb->flags & TVBUFF_FRAGMENT) {
				exception = FragmentBoundsError;
			}
			else {
				exception = ReportedBoundsError;
			}
			return exception;
		}
		else if ((guint)-offset > tvb->length) {
			return BoundsError;
		}
		else {
			*offset_ptr = tvb->length + offset;
		}
	}

	return 0;
}




static int
check_offset_length_no_exception(const tvbuff_t *tvb,
	const gint offset, gint const length_val,
	guint *offset_ptr, guint *length_ptr)
{
	guint end_offset;
	int exception;

	DISSECTOR_ASSERT(offset_ptr);
	DISSECTOR_ASSERT(length_ptr);

	/* Compute the offset */
	exception = compute_offset(tvb, offset, offset_ptr);
	if (exception)
		return exception;

	if (length_val < -1) {
		/* XXX - ReportedBoundsError? */
		return BoundsError;
	}

	/* Compute the length */
	if (length_val == -1)
		*length_ptr = tvb->length - *offset_ptr;
	else
		*length_ptr = length_val;

	/*
	* Compute the offset of the first byte past the length.
	*/
	end_offset = *offset_ptr + *length_ptr;

	/*
	* Check for an overflow
	*/
	if (end_offset < *offset_ptr)
		exception = BoundsError;
	/*else
	exception = validate_offset(tvb, end_offset); */

	return exception;
}



static const guint8*
ensure_contiguous_no_exception(tvbuff_t *tvb, const gint offset, const gint length, int *pexception)
{
	guint abs_offset, abs_length;
	int exception;

//vb_ops *ops = (tvb_ops *)malloc(sizeof(tvb_ops*));
	tvb_ops *ops = NULL;

tvb = (tvbuff_t *)malloc(sizeof(tvbuff_t *));
	exception = check_offset_length_no_exception(tvb, offset, length, &abs_offset, &abs_length);
	if (exception) {
		if (pexception)
			*pexception = exception;
		return NULL;
	}

	/*
	* We know that all the data is present in the tvbuff, so
	* no exceptions should be thrown.
	*/
	if (tvb->real_data)
		return tvb->real_data + abs_offset;

//if (ops->tvb_get_ptr)
//return ops->tvb_get_ptr(tvb, abs_offset, abs_length);

	//DISSECTOR_ASSERT_NOT_REACHED();
	return NULL;
}

static const guint8*
ensure_contiguous(tvbuff_t *tvb, const gint offset, const gint length)
{
	int           exception = 0;
	const guint8 *p;

	p = ensure_contiguous_no_exception(tvb, offset, length, &exception);
	if (p == NULL) {
		//DISSECTOR_ASSERT(exception > 0);
		//THROW(exception);
	}
	return p;
}

const guint8*
tvb_get_ptr(tvbuff_t *tvb, const gint offset, const gint length)
{
	return ensure_contiguous(tvb, offset, length);
}


static const guint8*
fast_ensure_contiguous(tvbuff_t *tvb, const gint offset, const guint length)
{
	guint end_offset;
	guint u_offset;

	DISSECTOR_ASSERT(tvb && tvb->initialized);
	// We don't check for overflow in this fast path so we only handle simple types 
	DISSECTOR_ASSERT(length <= 8);

/*if (offset < 0 || !tvb->real_data) {
		return ensure_contiguous(tvb, offset, length);
	} */

	u_offset = offset;
	end_offset = u_offset + length;

	if (end_offset <= tvb->length) {
		return tvb->real_data + u_offset;
	}

	if (end_offset > tvb->reported_length) {
		//if (tvb->flags & TVBUFF_FRAGMENT) {
		//THROW(FragmentBoundsError);
		fprintf(stderr, "Error occured in fast_ensure_contiguous");
	}
	//else {
	//THROW(ReportedBoundsError);
	//}
	/* not reached */

	//THROW(BoundsError);
	/* not reached */
	return NULL;
}

guint32
tvb_get_letoh24(tvbuff_t *tvb, const gint offset)
{
	const guint8 *ptr;

	ptr = fast_ensure_contiguous(tvb, offset, 3);
	return pletoh24(ptr);
}



static guint8
tvb_get_guint8(tvbuff_t *tvb, const gint offset)
{
	const guint8 *ptr;

	if (offset <= tvb->length) {
		ptr = fast_ensure_contiguous(tvb, offset, sizeof(guint8));
		return *ptr;
	}
	else
		return NULL;

}

void
expert_add_info(proto_item *pi, expert_field *expindex)
{
	expert_field_info* eiinfo;

	/* Look up the item */
	//EXPERT_REGISTRAR_GET_NTH(expindex->ei, eiinfo);

	//expert_set_info_vformat(pinfo, pi, eiinfo->group, eiinfo->severity, *eiinfo->hf_info.p_id, FALSE, eiinfo->summary, NULL);
}

tvbuff_t *
tvb_new_subset(tvbuff_t *backing, const gint backing_offset, const gint backing_length, const gint reported_length)
{
	tvbuff_t *tvb = NULL;
	guint	  subset_tvb_offset;
	guint	  subset_tvb_length;

	DISSECTOR_ASSERT(backing && backing->initialized);

	THROW_ON(reported_length < -1, ReportedBoundsError);
	//
	//tvb_check_offset_length(backing, backing_offset, backing_length,
	//		&subset_tvb_offset,
	//		&subset_tvb_length);

	//tvb = tvb_new_with_subset(backing, reported_length,
	//subset_tvb_offset, subset_tvb_length);

	//tvb_add_to_chain(backing, tvb);

	return tvb;
}

guint16
tvb_get_ntohs(tvbuff_t *tvb, const gint offset)
{
	const guint8 *ptr;

	ptr = fast_ensure_contiguous(tvb, offset, sizeof(guint16));
	return pntohs(ptr);
}


gboolean
tvb_bytes_exist(const tvbuff_t *tvb, const gint offset, const gint length)
{
	guint abs_offset, abs_length;
	int exception;

	DISSECTOR_ASSERT(tvb && tvb->initialized);

	exception = check_offset_length_no_exception(tvb, offset, length, &abs_offset, &abs_length);
	if (exception)
		return FALSE;

	return TRUE;
}

const gchar*
try_val_to_str_idx(const guint32 val, const value_string *vs, gint *idx)
{
	gint i = 0;

	DISSECTOR_ASSERT(idx != NULL);

	if (vs) {
		while (vs[i].strptr) {
			if (vs[i].value == val) {
				*idx = i;
				return(vs[i].strptr);
			}
			i++;
		}
	}

	*idx = -1;
	return NULL;
}


/* Like try_val_to_str_idx(), but doesn't return the index. */
const gchar*
try_val_to_str(const guint32 val, const value_string *vs)
{
	gint ignore_me;
	return try_val_to_str_idx(val, vs, &ignore_me);
}


const gchar*
val_to_str_const(const guint32 val, const value_string *vs,
	const char *unknown_str)
{
	const gchar *ret;

	DISSECTOR_ASSERT(unknown_str != NULL);

	ret = try_val_to_str(val, vs);
	if (ret != NULL)
		return ret;

	return unknown_str;
}

void
dissect_e164_cc(tvbuff_t *tvb, proto_tree *tree, int offset, gboolean bcd_coded) {

	int	cc_offset;
	guint8	address_digit_pair;
	guint16	id_code;
	guint8	cc_length;
	guint8	length;
	guint16 cc;

	cc_offset = offset;
	address_digit_pair = tvb_get_guint8(tvb, cc_offset);

	if (!bcd_coded) {
		/* Dissect country code after removing non significant zeros */
		while (address_digit_pair == 0) {
			cc_offset = cc_offset + 1;
			address_digit_pair = tvb_get_guint8(tvb, cc_offset);
		}
		cc = tvb_get_ntohs(tvb, cc_offset);
		if ((address_digit_pair & 0xf0) != 0) {
			cc = cc >> 4;
		}
	}
	else {
		cc = address_digit_pair & 0x0f;
		cc = cc << 4;
		cc = cc | (address_digit_pair & 0xf0) >> 4;
		cc = cc << 4;
		if (tvb_bytes_exist(tvb, cc_offset + 1, 1)) {
			address_digit_pair = tvb_get_guint8(tvb, cc_offset + 1);
			cc = cc | (address_digit_pair & 0x0f);
		}

	}

	switch (cc & 0x0f00) {

	case 0x0:
		cc_length = 1;
		break;

	case 0x0100:
		cc_length = 1;
		break;

	case 0x0200:
		switch (cc & 0x00f0) {
		case 0:
		case 0x70:
			cc_length = 2;
			break;
		default:
			cc_length = 3;
			break;
		}
		break;

	case 0x0300:
		switch (cc & 0x00f0) {
		case 0:
		case 0x10:
		case 0x20:
		case 0x30:
		case 0x40:
		case 0x60:
		case 0x90:
			cc_length = 2;
			break;
		default:
			cc_length = 3;
			break;
		}
		break;
	case 0x0400:
		switch (cc & 0x00f0) {
		case 0x20:
			cc_length = 3;
			break;
		default:
			cc_length = 2;
			break;
		}
		break;

	case 0x0500:
		switch (cc & 0x00f0) {
		case 0:
		case 0x90:
			cc_length = 3;
			break;
		default:
			cc_length = 2;
			break;
		}
		break;

	case 0x0600:
		switch (cc & 0x00f0) {
		case 0x70:
		case 0x80:
		case 0x90:
			cc_length = 3;
			break;
		default:
			cc_length = 2;
			break;
		}
		break;

	case 0x0700:
		cc_length = 1;
		break;

	case 0x0800:
		switch (cc & 0x00f0) {
		case 0x10:
		case 0x20:
		case 0x40:
		case 0x60:
			cc_length = 2;
			break;
		default:
			cc_length = 3;
			break;
		}
		break;

	case 0x0900:
		switch (cc & 0x00f0) {
		case 0:
		case 0x10:
		case 0x20:
		case 0x30:
		case 0x40:
		case 0x50:
		case 0x80:
			cc_length = 2;
			break;
		default:
			cc_length = 3;
			break;
		}
		break;

	default:
		cc_length = 0;
		break;
	}/* End switch cc */

	switch (cc_length) {
	case 1:
		cc = cc >> 8;
		length = 1;
		break;
	case 2:
		cc = cc >> 4;
		length = 1;
		break;
	default:
		length = 2;
		break;
	}/* end switch cc_length */

	 //proto_tree_add_text(tree, tvb, cc_offset, length, "Country Code: %x %s (length %u)", cc,
	 //val_to_str_ext_const(cc, &E164_country_code_value_ext, "Unknown"), cc_length);

	switch (cc) {
	case 0x881:
		if (!bcd_coded) {
			id_code = tvb_get_guint8(tvb, cc_offset + 1) & 0x0f;
		}
		else {
			id_code = (tvb_get_guint8(tvb, cc_offset + 1) & 0xf0) >> 4;
		}
		proto_tree_add_text(tree, tvb, (cc_offset + 1), 1, "Identification Code: %x %s ", id_code,
			val_to_str_const(id_code, E164_GMSS_vals, "Unknown"));
		break;
	case 0x882:
		if (!bcd_coded) {
			id_code = tvb_get_ntohs(tvb, cc_offset + 1);
			id_code = (id_code & 0x0ff0) >> 4;
		}
		else {
			id_code = tvb_get_guint8(tvb, cc_offset + 1) & 0xf0;
			id_code |= tvb_get_guint8(tvb, cc_offset + 2) & 0x0f;
		}
		//proto_tree_add_text(tree, tvb, (cc_offset + 1), 2, "Identification Code: %x %s ", id_code,
		//val_to_str_ext_const(id_code, &E164_International_Networks_882_vals_ext, "Unknown"));
		break;
	case 0x883:
		if (!bcd_coded) {
			id_code = tvb_get_ntohs(tvb, cc_offset + 1);
			id_code = id_code & 0x0fff;
		}
		else {
			id_code = (tvb_get_guint8(tvb, cc_offset + 1) & 0xf0) << 4;
			id_code |= (tvb_get_guint8(tvb, cc_offset + 2) & 0x0f) << 4;
			id_code |= (tvb_get_guint8(tvb, cc_offset + 2) & 0xf0) >> 4;
		}
		if ((id_code & 0x0ff0) == 0x510) {
			if (!bcd_coded) {
				id_code = (id_code << 4) | ((tvb_get_guint8(tvb, cc_offset + 3) & 0xf0) >> 4);
			}
			else {
				id_code = (id_code << 4) | (tvb_get_guint8(tvb, cc_offset + 3) & 0x0f);
			}
			//proto_tree_add_text(tree, tvb, (cc_offset + 1), 3, "Identification Code: %x %s ", id_code,
			//val_to_str_const(id_code, E164_International_Networks_883_vals, "Unknown"));
		}
		else {
			proto_tree_add_text(tree, tvb, (cc_offset + 1), 2, "Identification Code: %x %s ", id_code,
				val_to_str_const(id_code, E164_International_Networks_883_vals, "Unknown"));
		}
		break;
	default:
		break;
	}

}


static gsize g_strlcat(gchar       *dest, const gchar *src, gsize        dest_size)
{
	register gchar *d = dest;
	register const gchar *s = src;
	register gsize bytes_left = dest_size;
	gsize dlength;  /* Logically, MIN (strlen (d), dest_size) */

					//g_return_val_if_fail (dest != NULL, 0);
					//g_return_val_if_fail (src  != NULL, 0);
	if (dest != NULL || src != NULL)
		return 0;

	/* Find the end of dst and adjust bytes left but don't go past end */
	while (*d != 0 && bytes_left-- != 0)
		d++;
	dlength = d - dest;
	bytes_left = dest_size - dlength;

	if (bytes_left == 0)
		return dlength + strlen(s);

	while (*s != 0)
	{
		if (bytes_left != 1)
		{
			*d++ = *s;
			bytes_left--;
		}
		s++;
	}
	*d = 0;

	return dlength + (s - src);  /* count does not include NUL */
}


static const gchar* match_strval_idx(const guint32 val, const value_string *vs, gint *idx) {
	gint i = 0;

	if (vs) {
		while (vs[i].strptr) {
			if (vs[i].value == val) {
				*idx = i;
				return(vs[i].strptr);
			}
			i++;
		}
	}

	*idx = -1;
	return NULL;
}

static const gchar* match_strval(const guint32 val, const value_string *vs) {
	gint ignore_me;
	return match_strval_idx(val, vs, &ignore_me);
}


static gchar * emem_strdup_vprintf(const gchar *fmt, va_list ap, void *allocator(size_t))
{
	va_list ap2;
	gsize len = 0;
	gchar* dst;

	//G_VA_COPY(ap2, ap);

	//len = g_printf_string_upper_bound(fmt, ap);

	dst = (gchar *)allocator(len + 1);
	//g_vsnprintf (dst, (gulong) len, fmt, ap2);
	va_end(ap2);

	return dst;
}


static gchar *ep_strdup_vprintf(const gchar *fmt, va_list ap)
{
	return emem_strdup_vprintf(fmt, ap, malloc);// ep_alloc);
}

static gchar * ep_strdup_printf(const gchar *fmt, ...)
{
	va_list ap = 0;
	gchar *dst;

	//va_start(ap, fmt);
	dst = ep_strdup_vprintf(fmt, ap);
	//va_end(ap);
	return dst;
}


static const gchar* val_to_str(const guint32 val, const value_string *vs, const char *fmt) {
	const gchar *ret;

	g_assert(fmt != NULL);

	ret = match_strval(val, vs);
	if (ret != NULL)
		return ret;

	return ep_strdup_printf(fmt, val);
}


static gchar * emem_strdup(const gchar *src, void *allocator(size_t))
{
	guint len;
	gchar *dst;

	/* If str is NULL, just return the string "<NULL>" so that the callers don't
	* have to bother checking it.
	*/
	if (!src)
		return "<NULL>";

	len = (guint)strlen(src);
	dst = (gchar *)memcpy(allocator(len + 1), src, len + 1);

	return dst;
}


static void emem_scrub_memory(char *buf, size_t size, gboolean alloc)
{
	guint scrubbed_value;
	guint offset;

	if (!debug_use_memory_scrubber)
		return;

	if (alloc) /* this memory is being allocated */
		scrubbed_value = 0xBADDCAFE;
	else /* this memory is being freed */
		scrubbed_value = 0xDEADBEEF;

	/*  We shouldn't need to check the alignment of the starting address
	*  since this is malloc'd memory (or 'pagesize' bytes into malloc'd
	*  memory).
	*/

	/* XXX - if the above is *NOT* true, we should use memcpy here,
	* in order to avoid problems on alignment-sensitive platforms, e.g.
	* http://stackoverflow.com/questions/108866/is-there-memset-that-accepts-integers-larger-than-char
	*/

	for (offset = 0; offset + sizeof(guint) <= size; offset += sizeof(guint))
		*(guint*)(void*)(buf + offset) = scrubbed_value;

	/* Initialize the last bytes, if any */
	if (offset < size) {
		*(guint8*)(buf + offset) = scrubbed_value >> 24;
		offset++;
		if (offset < size) {
			*(guint8*)(buf + offset) = (scrubbed_value >> 16) & 0xFF;
			offset++;
			if (offset < size) {
				*(guint8*)(buf + offset) = (scrubbed_value >> 8) & 0xFF;
			}
		}
	}


}

static void * emem_alloc(size_t size, emem_header_t *mem)
{
	void *buf = mem->memory_alloc(size, mem);

	/*  XXX - this is a waste of time if the allocator function is going to
	*  memset this straight back to 0.
	*/
	emem_scrub_memory((char*)buf, size, TRUE);

	return buf;
}

static void * ep_alloc(size_t size)
{
	return emem_alloc(size, &ep_packet_mem);
}

static gchar * ep_strdup(const gchar *src)
{
	return emem_strdup(src, ep_alloc);
}



guint
tvb_length(const tvbuff_t *tvb)
{
	DISSECTOR_ASSERT(tvb && tvb->initialized);

	return tvb->length;
}

static char *unpack_digits(tvbuff_t *tvb, int offset) {

	int length;
	guint8 octet;
	int i = 0;
	int ii = 0, myoff = 0;
	char *digit_str;
	length = tvb_length(tvb);
	if (length < offset)
		return "";
	digit_str = (char *)malloc(sizeof((length - offset) * 2 + 1));//ep_alloc
	myoff = offset;
	//for(ii=0;ii < 8; ii++)
	// {

	//	 printf("%0x\t",tvb->real_data[myoff]);
	//	 myoff++;
	// }
	//fprintf(stderr,"\n");
	while (offset < length) {

		octet = tvb_get_guint8(tvb, offset);
		digit_str[i] = ((octet & 0x0f) + '0');
		i++;

		/*
		* unpack second value in byte
		*/
		octet = octet >> 4;

		if (octet == 0x0f)	/* odd number bytes - hit filler */
			break;

		digit_str[i] = ((octet & 0x0f) + '0');
		//fprintf(stderr,"%c",digit_str[i]);
		i++;
		offset++;

	}
	digit_str[i] = '\0';
	return digit_str;
}

static void*   dissect_sccp_gt_address_information(tvbuff_t *tvb, guint length, gboolean even_length, gboolean called, gboolean route_on_gt, SS7_target*  target)
{
	guint offset = 0, size = 0;
	guint8 odd_signal, even_signal;
	//  proto_item *digits_item;
	//proto_tree *digits_tree;
	char *gt_digits;
	char  *digits;
	int ii = 0;

	gt_digits = (char *)malloc(GT_MAX_SIGNALS + 1);//ep_alloc0

	while (offset < length) {
		odd_signal = tvb_get_guint8(tvb, offset) & GT_ODD_SIGNAL_MASK;
		even_signal = tvb_get_guint8(tvb, offset) & GT_EVEN_SIGNAL_MASK;
		even_signal >>= GT_EVEN_SIGNAL_SHIFT;

		g_strlcat(gt_digits, val_to_str(odd_signal, sccp_address_signal_values,
			"Unknown: %d"), GT_MAX_SIGNALS + 1);

		/* If the last signal is NOT filler */
		if (offset != (length - 1) || even_length == TRUE)
			g_strlcat(gt_digits, val_to_str(even_signal, sccp_address_signal_values,
				"Unknown: %d"), GT_MAX_SIGNALS + 1);
		offset += GT_SIGNAL_LENGTH;
	}

	if (is_connectionless(message_type) && sccp_msg) {
		guint8 **gt_ptr = called ? &(sccp_msg->data.ud.called_gt) : &(sccp_msg->data.ud.calling_gt);

		*gt_ptr = (guint8 *)ep_strdup(gt_digits);
	}
	//digits = collect_digits(tvb,offset);
	//const char *
	digits = (char*)unpack_digits(tvb, 0);
	//digits_item = proto_tree_add_string(tree, called ? hf_sccp_called_gt_digits
	//                                    : hf_sccp_calling_gt_digits,
	//                                    tvb, 0, length, gt_digits);
	fprintf(stderr, "\t    %s: %s\n", called ? "Called Party Digits" : "Calling Party Digits", digits);

	//fprintf(stderr,": %s\n",digits);
	//digits_tree = proto_item_add_subtree(digits_item, called ? ett_sccp_called_gt_digits
	//                                     : ett_sccp_calling_gt_digits);

	//  if (set_addresses && route_on_gt) {
	//    if (called) {
	//		
	////      SET_ADDRESS(&pinfo->dst, AT_STRINGZ, 1+(int)strlen(gt_digits), gt_digits);
	//    } else {
	//      //SET_ADDRESS(&pinfo->src, AT_STRINGZ, 1+(int)strlen(gt_digits), gt_digits);
	//	     
	//    }
	//  }
	//proto_tree_add_string(digits_tree, hf_sccp_gt_digits, tvb, 0, length, gt_digits);"Called or Calling GT Digits"
	fprintf(stderr, "\t\tCalled or Calling GT Digits: %s\n", digits);
	//proto_tree_add_uint(digits_tree, called ? hf_sccp_called_gt_digits_length
	//                    : hf_sccp_calling_gt_digits_length,
	//                    tvb, 0, length, (guint32)strlen(gt_digits));
	//size = sizeof(digits)+1;
	fprintf(stderr, "\t\t%s :%d\n", called ? "Number of Called Party Digits"
		: "Number of Calling Party Digits",
		//size*2);
		(guint32)strlen((char *)digits));
	//return digits_tree;
	if (called == 1)
		target->calledParty_no = digits;
	else
		target->callingParty_no = digits;
	return 0;
}


static void
dissect_sccp_global_title(tvbuff_t *tvb, proto_tree *tree, guint length,
	guint8 gti, gboolean route_on_gt, gboolean called, SS7_target* target)
{
	proto_item *gt_item;
	proto_tree *gt_tree;
	proto_tree *digits_tree = NULL;
	tvbuff_t   *signals_tvb;
	guint       offset = 0;
	guint8      odd_even, nai = 0, np = 0, es;
	gboolean    even = TRUE;

	/* Shift GTI to where we can work with it */
	gti >>= GTI_SHIFT;

	//gt_item = proto_tree_add_text(tree, tvb, offset, length,
	//		"Global Title 0x%x (%u byte%s)",
	//		gti, length, plurality(length, "", "s"));
	//gt_tree = proto_item_add_subtree(gt_item, called ? ett_sccp_called_gt
	//: ett_sccp_calling_gt);

	/* Decode Transation Type (if present) */
	if ((gti == AI_GTI_TT) ||
		((decode_mtp3_standard != ANSI_STANDARD) &&
		((gti == ITU_AI_GTI_TT_NP_ES) || (gti == ITU_AI_GTI_TT_NP_ES_NAI))) ||
			((decode_mtp3_standard == ANSI_STANDARD) && (gti == ANSI_AI_GTI_TT_NP_ES))) {

		//proto_tree_add_item(gt_tree, called ? hf_sccp_called_gt_tt
		//	: hf_sccp_calling_gt_tt,
		//tvb, offset, GT_TT_LENGTH, ENC_NA);
		offset += GT_TT_LENGTH;
	}

	if (gti == AI_GTI_TT) {
		/* Protocol doesn't tell us, so we ASSUME even... */
		even = TRUE;
	}

	/* Decode Numbering Plan and Encoding Scheme (if present) */
	if (((decode_mtp3_standard != ANSI_STANDARD) &&
		((gti == ITU_AI_GTI_TT_NP_ES) || (gti == ITU_AI_GTI_TT_NP_ES_NAI))) ||
		((decode_mtp3_standard == ANSI_STANDARD) && (gti == ANSI_AI_GTI_TT_NP_ES))) {

		np = tvb_get_guint8(tvb, offset) & GT_NP_MASK;
		//proto_tree_add_uint(gt_tree, called ? hf_sccp_called_gt_np
		//: hf_sccp_calling_gt_np,
		//tvb, offset, GT_NP_ES_LENGTH, np);

		es = tvb_get_guint8(tvb, offset) & GT_ES_MASK;
		//proto_tree_add_uint(gt_tree, called ? hf_sccp_called_gt_es
		//: hf_sccp_calling_gt_es,
		//tvb, offset, GT_NP_ES_LENGTH, es);

		even = (es == GT_ES_BCD_EVEN) ? TRUE : FALSE;

		offset += GT_NP_ES_LENGTH;
	}

	/* Decode Nature of Address Indicator (if present) */
	if ((decode_mtp3_standard != ANSI_STANDARD) &&
		((gti == ITU_AI_GTI_NAI) || (gti == ITU_AI_GTI_TT_NP_ES_NAI))) {

		/* Decode Odd/Even Indicator (if present) */
		if (gti == ITU_AI_GTI_NAI) {
			odd_even = tvb_get_guint8(tvb, offset) & GT_OE_MASK;
			//proto_tree_add_uint(gt_tree, called ? hf_sccp_called_gt_oe
			//: hf_sccp_calling_gt_oe,
			//tvb, offset, GT_NAI_LENGTH, odd_even);
			even = (odd_even == GT_OE_EVEN) ? TRUE : FALSE;
		}

		nai = tvb_get_guint8(tvb, offset) & GT_NAI_MASK;
		//proto_tree_add_uint(gt_tree, called ? hf_sccp_called_gt_nai
		//: hf_sccp_calling_gt_nai,
		//tvb, offset, GT_NAI_LENGTH, nai);

		offset += GT_NAI_LENGTH;
	}

	/* Decode address signal(s) */
	if (length < offset)
		return;

	signals_tvb = tvb_new_subset(tvb, offset, (length - offset),
		(length - offset));

	dissect_sccp_gt_address_information(signals_tvb,
		(length - offset),
		even, called, route_on_gt, target);

	/* Display the country code (if we can) */
	switch (np >> GT_NP_SHIFT) {
	case GT_NP_ISDN:
	case GT_NP_ISDN_MOBILE:
		if (nai == GT_NAI_INTERNATIONAL_NUM) {
			dissect_e164_cc(signals_tvb, digits_tree, 0, TRUE);
		}
		break;
	case GT_NP_LAND_MOBILE:
		//dissect_e212_mcc_mnc_in_address(signals_tvb, digits_tree, 0);
		break;
	default:
		break;
	}
}


static int
dissect_sccp_3byte_pc(tvbuff_t *tvb, proto_tree *call_tree, guint offset,
	gboolean called)
{
	int hf_pc;

	if (decode_mtp3_standard == ANSI_STANDARD)
	{
		if (called)
			hf_pc = hf_sccp_called_ansi_pc;
		else
			hf_pc = hf_sccp_calling_ansi_pc;
	}
	else /* CHINESE_ITU_STANDARD */ {
		if (called)
			hf_pc = hf_sccp_called_chinese_pc;
		else
			hf_pc = hf_sccp_calling_chinese_pc;
	}

	/* create and fill the PC tree */
	//dissect_mtp3_3byte_pc(tvb, offset, call_tree,
	//called ? ett_sccp_called_pc : ett_sccp_calling_pc,
	//hf_pc,
	//called ? hf_sccp_called_pc_network : hf_sccp_calling_pc_network,
	//called ? hf_sccp_called_pc_cluster : hf_sccp_calling_pc_cluster,
	//called ? hf_sccp_called_pc_member : hf_sccp_calling_pc_member,
	//0, 0);

	return(offset + ANSI_PC_LENGTH);
}

/* Find an entry in a uint dissector table. */
static dtbl_entry_t *
find_uint_dtbl_entry(dissector_table_t sub_dissectors, const guint32 pattern)
{
	switch (sub_dissectors->type) {

	case FT_UINT8:
	case FT_UINT16:
	case FT_UINT24:
	case FT_UINT32:
		/*
		* You can do a uint lookup in these tables.
		*/
		break;

		//default:
		/*
		* But you can't do a uint lookup in any other types
		* of tables.
		*/
		//g_assert_not_reached();
	}

	/*
	* Find the entry.
	*/
	//return (dtbl_entry_t *)g_hash_table_lookup(sub_dissectors->hash_table,
	//GUINT_TO_POINTER(pattern));
	return NULL;
}


/* Look for a given value in a given uint dissector table and, if found,
return the dissector handle for that value. */
dissector_handle_t
dissector_get_uint_handle(dissector_table_t const sub_dissectors, const guint32 uint_val)
{
	dtbl_entry_t *dtbl_entry;

	dtbl_entry = find_uint_dtbl_entry(sub_dissectors, uint_val);
	if (dtbl_entry != NULL)
		return dtbl_entry->current;
	else
		return NULL;
}

/* Get the short name of the protocol for a dissector handle, if it has
a protocol. */
const char *
dissector_handle_get_short_name(const dissector_handle_t handle)
{
	if (handle->protocol == NULL) {
		/*
		* No protocol (see, for example, the handle for
		* dissecting the set of protocols where the first
		* octet of the payload is an OSI network layer protocol
		* ID).
		*/
		return NULL;
	}
	//return proto_get_protocol_short_name(handle->protocol);
}



/*  FUNCTION dissect_sccp_called_calling_param():
*  Dissect the Calling or Called Party Address parameters.
*
*  The boolean 'called' describes whether this function is decoding a
*  called (TRUE) or calling (FALSE) party address.  There is simply too
*  much code in this function to have 2 copies of it (one for called, one
*  for calling).
*
*  NOTE:  this function is called even when (!tree) so that we can get
*  the SSN and subsequently call subdissectors (if and when there's a data
*  parameter).  Realistically we should put if (!tree)'s around a lot of the
*  code, but I think that would make it unreadable--and the expense of not
*  doing so does not appear to be very high.
*/
static void
dissect_sccp_called_calling_param(tvbuff_t *tvb,
	guint length, gboolean called, SS7_target * target, guint16 offset)
{
	proto_item *call_item = 0, *call_ai_item = 0, *item, *hidden_item, *expert_item;
	proto_tree *call_tree = 0, *call_ai_tree = 0;
//guint offset;
	guint8 national = 0xFFU, routing_ind, gti, pci, ssni, ssn;
	tvbuff_t *gt_tvb;
	dissector_handle_t ssn_dissector = NULL, tcap_ssn_dissector = NULL;
	const char *ssn_dissector_short_name = NULL;
	const char *tcap_ssn_dissector_short_name = NULL;

	/* call_item = proto_tree_add_text(tree, tvb, 0, length,
	"%s Party address (%u byte%s)",
	called ? "Called" : "Calling", length,
	plurality(length, "", "s")); */
	//call_tree = proto_item_add_subtree(call_item, called ? ett_sccp_called : ett_sccp_calling);

	//call_ai_item = proto_tree_add_text(call_tree, tvb, 0,
		//ADDRESS_INDICATOR_LENGTH,
		//"Address Indicator");
	//call_ai_tree = proto_item_add_subtree(call_ai_item, called ? ett_sccp_called_ai : ett_sccp_calling_ai);

	if (decode_mtp3_standard == ANSI_STANDARD) {
		national = tvb_get_guint8(tvb, offset) & ANSI_NATIONAL_MASK;
		printf("National indicator: %u \n  ", national);
		//expert_item = proto_tree_add_uint(call_ai_tree, called ? hf_sccp_called_ansi_national_indicator
			//: hf_sccp_calling_ansi_national_indicator,
			//tvb, 0, ADDRESS_INDICATOR_LENGTH, national);
		if (national == 0)
			//expert_add_info(expert_item, &ei_sccp_international_standard_address);
			printf(" **  ");
	}
	else {

		guint8 natl_use_bit = tvb_get_guint8(tvb, offset) & ITU_RESERVED_MASK;

		/*proto_tree_add_uint(call_ai_tree, called ? hf_sccp_called_itu_natl_use_bit
		: hf_sccp_calling_itu_natl_use_bit,
		tvb, 0, ADDRESS_INDICATOR_LENGTH, natl_use_bit); */
	}

	routing_ind = tvb_get_guint8(tvb, offset) & ROUTING_INDICATOR_MASK;
	printf("Routing indicator: %u \n  ", national);

	/*proto_tree_add_uint(call_ai_tree, called ? hf_sccp_called_routing_indicator : hf_sccp_calling_routing_indicator,
	tvb, 0, ADDRESS_INDICATOR_LENGTH, routing_ind); */
	/* Only shift off the other bits after adding the item */
	routing_ind >>= ROUTING_INDICATOR_SHIFT;

	gti = tvb_get_guint8(tvb, offset) & GTI_MASK;

	if (decode_mtp3_standard == ITU_STANDARD ||
		decode_mtp3_standard == CHINESE_ITU_STANDARD ||
		decode_mtp3_standard == JAPAN_STANDARD ||
		national == 0) {



		ssni = tvb_get_guint8(tvb, offset) & ITU_SSN_INDICATOR_MASK;
		//expert_item = proto_tree_add_uint(call_ai_tree,
			//called ? hf_sccp_called_itu_ssn_indicator : hf_sccp_calling_itu_ssn_indicator,
			//tvb, 0, ADDRESS_INDICATOR_LENGTH, ssni);
		if ((routing_ind == ROUTE_ON_SSN) && (ssni == 0)) {
			//expert_add_info(expert_item, &ei_sccp_no_ssn_present);
			printf("route on SSN");
		}

		pci = tvb_get_guint8(tvb, offset) & ITU_PC_INDICATOR_MASK;
		/*proto_tree_add_uint(call_ai_tree, called ? hf_sccp_called_itu_point_code_indicator : hf_sccp_calling_itu_point_code_indicator,
		tvb, 0, ADDRESS_INDICATOR_LENGTH, pci);*/

		offset = ADDRESS_INDICATOR_LENGTH;

		/* Dissect PC (if present) */
		if (pci) {
			if (decode_mtp3_standard == ITU_STANDARD || national == 0) {
				if (length < offset + ITU_PC_LENGTH) {
					//proto_tree_add_expert_format(call_tree, pinfo, &ei_sccp_wrong_length, tvb, 0, -1,
					//"Wrong length indicated (%u) should be at least %u, PC is %u octets",
					//length, offset + ITU_PC_LENGTH, ITU_PC_LENGTH);
					return;
				}
				//proto_tree_add_item(call_tree, called ? hf_sccp_called_itu_pc : hf_sccp_calling_itu_pc,
				//tvb, offset, ITU_PC_LENGTH, ENC_LITTLE_ENDIAN);
				offset += ITU_PC_LENGTH;

			}
			else if (decode_mtp3_standard == JAPAN_STANDARD) {

				if (length < offset + JAPAN_PC_LENGTH) {
					//proto_tree_add_expert_format(call_tree,  &ei_sccp_wrong_length, tvb, 0, -1,
					//"Wrong length indicated (%u) should be at least %u, PC is %u octets",
					//length, offset + JAPAN_PC_LENGTH, JAPAN_PC_LENGTH);
					return;
				}
				//proto_tree_add_item(call_tree, called ? hf_sccp_called_japan_pc : hf_sccp_calling_japan_pc,
				//tvb, offset, JAPAN_PC_LENGTH, ENC_LITTLE_ENDIAN);

				offset += JAPAN_PC_LENGTH;

			}
			else /* CHINESE_ITU_STANDARD */ {

				if (length < offset + ANSI_PC_LENGTH) {
					//proto_tree_add_expert_format(call_tree, pinfo, &ei_sccp_wrong_length, tvb, 0, -1,
					//"Wrong length indicated (%u) should be at least %u, PC is %u octets",
					//length, offset + ANSI_PC_LENGTH, ANSI_PC_LENGTH);
					return;
				}
				offset = dissect_sccp_3byte_pc(tvb, call_tree, offset, called);

			}
		}

		/* Dissect SSN (if present) */
		if (ssni) {
			ssn = tvb_get_guint8(tvb, offset);

			if ((routing_ind == ROUTE_ON_SSN) && (ssn == 0)) {
				expert_add_info(expert_item, &ei_sccp_ssn_zero);
			}

			if (called && assoc)
				assoc->called_ssn = ssn;
			else if (assoc)
				assoc->calling_ssn = ssn;

			if (is_connectionless(message_type) && sccp_msg) {
				guint *ssn_ptr = called ? &(sccp_msg->data.ud.called_ssn) : &(sccp_msg->data.ud.calling_ssn);

				*ssn_ptr = ssn;
			}


			//PROTO_ITEM_SET_HIDDEN(hidden_item);

			offset += ADDRESS_SSN_LENGTH;

			/* Get the dissector handle of the dissector registered for this ssn
			* And print its name.
			*/
			ssn_dissector = dissector_get_uint_handle(sccp_ssn_dissector_table, ssn);

			if (ssn_dissector) {
				ssn_dissector_short_name = dissector_handle_get_short_name(ssn_dissector);

				if (ssn_dissector_short_name) {
					//item = proto_tree_add_text(call_tree, tvb, offset - 1, ADDRESS_SSN_LENGTH,
						//"Linked to %s", ssn_dissector_short_name);
					//PROTO_ITEM_SET_GENERATED(item);

					/*	if (g_ascii_strncasecmp("TCAP", ssn_dissector_short_name, 4) == 0) {
					//					tcap_ssn_dissector = get_itu_tcap_subdissector(ssn);
					//			}

					if (tcap_ssn_dissector) {
					tcap_ssn_dissector_short_name = dissector_handle_get_short_name(tcap_ssn_dissector);
					//proto_item_append_text(item, ", TCAP SSN linked to %s", tcap_ssn_dissector_short_name);
					}
					} */
				} /* short name */
			} /* ssn_dissector */
		} /* ssni */

		  /* Dissect GT (if present) */
		if (gti != AI_GTI_NO_GT) {
			if (length < offset)
				return;

			gt_tvb = tvb_new_subset(tvb, offset, (length - offset),
				(length - offset));
			dissect_sccp_global_title(gt_tvb, call_tree, (length - offset), gti,
				(routing_ind == ROUTE_ON_GT), called, target);
		}

	}
	else if (decode_mtp3_standard == ANSI_STANDARD) {

		//proto_tree_add_uint(call_ai_tree, called ? hf_sccp_called_ansi_global_title_indicator
		//	: hf_sccp_calling_ansi_global_title_indicator,
		//	tvb, 0, ADDRESS_INDICATOR_LENGTH, gti);

		pci = tvb_get_guint8(tvb, 0) & ANSI_PC_INDICATOR_MASK;
		//proto_tree_add_uint(call_ai_tree, called ? hf_sccp_called_ansi_point_code_indicator
		//	: hf_sccp_calling_ansi_point_code_indicator,
			//tvb, 0, ADDRESS_INDICATOR_LENGTH, pci);

		ssni = tvb_get_guint8(tvb, offset) & ANSI_SSN_INDICATOR_MASK;
		//expert_item = proto_tree_add_uint(call_ai_tree, called ? hf_sccp_called_ansi_ssn_indicator
			//: hf_sccp_calling_ansi_ssn_indicator,
			//tvb, 0, ADDRESS_INDICATOR_LENGTH, ssni);
		if ((routing_ind == ROUTE_ON_SSN) && (ssni == 0)) {
			//expert_add_info(expert_item, &ei_sccp_no_ssn_present);
		}

		offset = ADDRESS_INDICATOR_LENGTH;

		/* Dissect SSN (if present) */
		if (ssni) {
			ssn = tvb_get_guint8(tvb, offset);

			if ((routing_ind == ROUTE_ON_SSN) && (ssn == 0)) {
				expert_add_info(expert_item, &ei_sccp_ssn_zero);
			}

			if (called && assoc) {
				assoc->called_ssn = ssn;
			}
			else if (assoc) {
				assoc->calling_ssn = ssn;
			}

			if (is_connectionless(message_type) && sccp_msg) {
				guint *ssn_ptr = called ? &(sccp_msg->data.ud.called_ssn) : &(sccp_msg->data.ud.calling_ssn);

				*ssn_ptr = ssn;
			}

			

			offset += ADDRESS_SSN_LENGTH;
		}

		/* Dissect PC (if present) */
		if (pci) {
			offset = dissect_sccp_3byte_pc(tvb, call_tree, offset, called);
		}

		/* Dissect GT (if present) */
		if (gti != AI_GTI_NO_GT) {
			if (length < offset)
				return;
			gt_tvb = tvb_new_subset(tvb, offset, (length - offset),
				(length - offset));
			dissect_sccp_global_title(gt_tvb, call_tree, (length - offset), gti,
				(routing_ind == ROUTE_ON_GT), called, target);
		}

	}

}

static void
dissect_sccp_called_param(tvbuff_t *tvb, guint length, SS7_target* target,guint16 offset)

{
	dissect_sccp_called_calling_param(tvb, length, TRUE, target,  offset);
}


static void
dissect_sccp_calling_param(tvbuff_t *tvb, guint length, SS7_target* target, guint16 offset)
{
	dissect_sccp_called_calling_param(tvb, length, FALSE, target, offset);
}


static void
dissect_sccp_dlr_param(tvbuff_t *tvb, guint length)
{
	proto_item *lr_item;

	/*if (length != 3) {
	proto_tree_add_expert_format(tree, pinfo, &ei_sccp_wrong_length, tvb, 0, length,
	"Wrong length indicated. Expected 3, got %u", length);
	return;
	} */

	dlr = tvb_get_letoh24(tvb, 0);
	//proto_tree_add_uint(tree, hf_sccp_dlr, tvb, 0, length, dlr);
	//lr_item = proto_tree_add_uint(tree, hf_sccp_lr, tvb, 0, length, dlr);
	//PROTO_ITEM_SET_HIDDEN(lr_item);

	//if (show_key_params)
	//col_append_fstr(COL_INFO, "DLR=%d ", dlr);
}


static void
dissect_sccp_slr_param(tvbuff_t *tvb, guint length)
{
	proto_item *lr_item;

	/*if (length != 3) {
	proto_tree_add_expert_format(tree, pinfo, &ei_sccp_wrong_length, tvb, 0, length,
	"Wrong length indicated. Expected 3, got %u", length);
	return;
	} */

	slr = tvb_get_letoh24(tvb, 0);
	//proto_tree_add_uint(tree, hf_sccp_slr, tvb, 0, length, slr);
	//lr_item = proto_tree_add_uint(tree, hf_sccp_lr, tvb, 0, length, slr);
	//PROTO_ITEM_SET_HIDDEN(lr_item);

	//if (show_key_params)
	//col_append_fstr(COL_INFO, "SLR=%d ", slr);
}


static void
dissect_sccp_class_param(tvbuff_t *tvb, guint length,  guint16 offset)
{
	guint8      msg_class;
	proto_item *pi = (proto_item *)malloc(sizeof(proto_item *));
	gboolean    invalid_class = FALSE;

	/*if (length != 1) {
	proto_tree_add_expert_format(tree, pinfo, &ei_sccp_wrong_length, tvb, 0, length,
	"Wrong length indicated. Expected 1, got %u", length);
	return;
	} */

	msg_class = tvb_get_guint8(tvb, offset) & CLASS_CLASS_MASK;
	printf("message type %u \n ",msg_class );
	//pi = proto_tree_add_uint(tree, hf_sccp_class, tvb, 0, length, msg_class);

	switch (message_type) {
	case SCCP_MSG_TYPE_DT1:
		if (msg_class != 2)
			invalid_class = TRUE;
		break;
	case SCCP_MSG_TYPE_DT2:
	case SCCP_MSG_TYPE_AK:
	case SCCP_MSG_TYPE_ED:
	case SCCP_MSG_TYPE_EA:
	case SCCP_MSG_TYPE_RSR:
	case SCCP_MSG_TYPE_RSC:
		if (msg_class != 3)
			invalid_class = TRUE;
		break;
	case SCCP_MSG_TYPE_CR:
	case SCCP_MSG_TYPE_CC:
	case SCCP_MSG_TYPE_CREF:
	case SCCP_MSG_TYPE_RLSD:
	case SCCP_MSG_TYPE_RLC:
	case SCCP_MSG_TYPE_ERR:
	case SCCP_MSG_TYPE_IT:
		if ((msg_class != 2) && (msg_class != 3))
			invalid_class = TRUE;
		break;
	case SCCP_MSG_TYPE_UDT:
	case SCCP_MSG_TYPE_UDTS:
	case SCCP_MSG_TYPE_XUDT:
	case SCCP_MSG_TYPE_XUDTS:
	case SCCP_MSG_TYPE_LUDT:
	case SCCP_MSG_TYPE_LUDTS:
		if ((msg_class != 0) && (msg_class != 1))
			invalid_class = TRUE;
		break;
	}

	if (invalid_class)
		expert_add_info(pi, &ei_sccp_class_unexpected);

	if (msg_class == 0 || msg_class == 1) {
		guint8 handling = tvb_get_guint8(tvb, offset) & CLASS_SPARE_HANDLING_MASK;

		//pi = proto_tree_add_item(tree, hf_sccp_handling, tvb, 0, length, ENC_NA);
		handling >>= CLASS_SPARE_HANDLING_SHIFT;
		printf("message handling %u \n ", handling);
		if (try_val_to_str(handling, sccp_class_handling_values) == NULL) {
	//expert_add_info(NULL, &ei_sccp_handling_invalid);
		}
	}
}


static void
dissect_sccp_segmenting_reassembling_param(tvbuff_t *tvb, proto_tree *tree, guint length)
{
	//if (length != 1) {
	//proto_tree_add_expert_format(tree, pinfo, &ei_sccp_wrong_length, tvb, 0, length,
	//	"Wrong length indicated. Expected 1, got %u", length);
	//return;
	//}

	//proto_tree_add_item(tree, hf_sccp_more, tvb, 0, length, ENC_BIG_ENDIAN);
}

static void
dissect_sccp_receive_sequence_number_param(tvbuff_t *tvb, guint length)
{
	guint8 rsn;

	/*if (length != 1) {
	proto_tree_add_expert_format(tree, pinfo, &ei_sccp_wrong_length, tvb, 0, length,
	"Wrong length indicated. Expected 1, got %u", length);
	return;
	} */

	rsn = tvb_get_guint8(tvb, 0) >> 1;
	//proto_tree_add_uint(tree, hf_sccp_rsn, tvb, 0, length, rsn);
}


static void
dissect_sccp_sequencing_segmenting_param(tvbuff_t *tvb, guint length)
{
	guint8      rsn, ssn;
	//proto_item *param_item;
	//proto_tree *param_tree;

	ssn = tvb_get_guint8(tvb, 0) >> 1;
	rsn = tvb_get_guint8(tvb, SEQUENCING_SEGMENTING_SSN_LENGTH) >> 1;

	/* param_item = proto_tree_add_text(tree, tvb, 0, length, "%s",
	val_to_str(PARAMETER_SEQUENCING_SEGMENTING,
	sccp_parameter_values, "Unknown: %d"));
	param_tree = proto_item_add_subtree(param_item,
	ett_sccp_sequencing_segmenting);

	proto_tree_add_uint(param_tree, hf_sccp_sequencing_segmenting_ssn, tvb, 0,
	SEQUENCING_SEGMENTING_SSN_LENGTH, ssn);
	proto_tree_add_uint(param_tree, hf_sccp_sequencing_segmenting_rsn, tvb,
	SEQUENCING_SEGMENTING_SSN_LENGTH,
	SEQUENCING_SEGMENTING_RSN_LENGTH, rsn);
	proto_tree_add_item(param_tree, hf_sccp_sequencing_segmenting_more, tvb,
	SEQUENCING_SEGMENTING_SSN_LENGTH,
	SEQUENCING_SEGMENTING_RSN_LENGTH, ENC_NA); */
}

static void
dissect_sccp_credit_param(tvbuff_t *tvb, guint length)
{
	if (length != 1) {
		//proto_tree_add_expert_format(tree, pinfo, &ei_sccp_wrong_length, tvb, 0, length,
		//"Wrong length indicated. Expected 1, got %u", length);
		return;
	}

	//proto_tree_add_item(tree, hf_sccp_credit, tvb, 0, length, ENC_NA);
}

static void
dissect_sccp_release_cause_param(tvbuff_t *tvb, guint length)
{
	if (length != 1) {
		//proto_tree_add_expert_format(tree, pinfo, &ei_sccp_wrong_length, tvb, 0, length,
		//"Wrong length indicated. Expected 1, got %u", length);
		return;
	}

	//proto_tree_add_item(tree, hf_sccp_release_cause, tvb, 0, length, ENC_LITTLE_ENDIAN);

	//if (show_key_params)
	//col_append_fstr(pinfo->cinfo, COL_INFO, "Cause=%d ", tvb_get_guint8(tvb, 0));
}


static void
dissect_sccp_return_cause_param(tvbuff_t *tvb, guint length)
{
	if (length != 1) {
		//proto_tree_add_expert_format(tree, pinfo, &ei_sccp_wrong_length, tvb, 0, length,
		//"Wrong length indicated. Expected 1, got %u", length);
		return;
	}

	//proto_tree_add_item(tree, hf_sccp_return_cause, tvb, 0, length, ENC_LITTLE_ENDIAN);

	//if (show_key_params)
	//col_append_fstr(COL_INFO, "Cause=%d ", tvb_get_guint8(tvb, 0));

}


static void
dissect_sccp_reset_cause_param(tvbuff_t *tvb, guint length)
{
	if (length != 1) {
		//proto_tree_add_expert_format(tree, pinfo, &ei_sccp_wrong_length, tvb, 0, length,
		//"Wrong length indicated. Expected 1, got %u", length);
		return;
	}

	//proto_tree_add_item(tree, hf_sccp_reset_cause, tvb, 0, length, ENC_LITTLE_ENDIAN);

	//if (show_key_params)
	//col_append_fstr(pinfo->cinfo, COL_INFO, "Cause=%d ", tvb_get_guint8(tvb, 0));
}

static void
dissect_sccp_error_cause_param(tvbuff_t *tvb, guint length)
{
	if (length != 1) {
		//proto_tree_add_expert_format(tree, pinfo, &ei_sccp_wrong_length, tvb, 0, length,
		//"Wrong length indicated. Expected 1, got %u", length);
		return;
	}

	//proto_tree_add_item(tree, hf_sccp_error_cause, tvb, 0, length, ENC_LITTLE_ENDIAN);

	//if (show_key_params)
	//col_append_fstr(pinfo->cinfo, COL_INFO, "Cause=%d ", tvb_get_guint8(tvb, 0));
}


static void
dissect_sccp_refusal_cause_param(tvbuff_t *tvb, guint length)
{
	if (length != 1) {
		//proto_tree_add_expert_format(tree, pinfo, &ei_sccp_wrong_length, tvb, 0, length,
		//"Wrong length indicated. Expected 1, got %u", length);
		return;
	}

	//proto_tree_add_item(tree, hf_sccp_refusal_cause, tvb, 0, length, ENC_LITTLE_ENDIAN);

	//if (show_key_params)
	//col_append_fstr(pinfo->cinfo, COL_INFO, "Cause=%d ", tvb_get_guint8(tvb, 0));
}

int
proto_item_get_len(const proto_item *pi)
{
	field_info *fi = PITEM_FINFO(pi);
	return fi ? fi->length : -1;
}

void
proto_item_set_len(proto_item *pi, const gint length)
{
	field_info *fi;

	if (pi == NULL)
		return;

	fi = PITEM_FINFO(pi);
	if (fi == NULL)
		return;

	DISSECTOR_ASSERT(length >= 0);
	fi->length = length;

	/*
	* You cannot just make the "len" field of a GByteArray
	* larger, if there's no data to back that length;
	* you can only make it smaller.
	*/
	if (fi->value.ftype->ftype == FT_BYTES && length <= (gint)fi->value.value.bytes->len)
		fi->value.value.bytes->len = length;
}


static void
dissect_sccp_segmentation_param(tvbuff_t *tvb, guint length)
{
	proto_item *param_item;
	proto_tree *param_tree;

	/*param_item = proto_tree_add_text(tree, tvb, 0, length, "%s",
	val_to_str(PARAMETER_SEGMENTATION,
	sccp_parameter_values, "Unknown: %d"));
	param_tree = proto_item_add_subtree(param_item, ett_sccp_segmentation);

	proto_tree_add_item(param_tree, hf_sccp_segmentation_first, tvb, 0, 1, ENC_NA);
	proto_tree_add_item(param_tree, hf_sccp_segmentation_class, tvb, 0, 1, ENC_NA);
	proto_tree_add_item(param_tree, hf_sccp_segmentation_remaining, tvb, 0, 1, ENC_NA); */

	if (length - 1 != 3) {
		//proto_tree_add_expert_format(tree, pinfo, &ei_sccp_wrong_length, tvb, 0, length - 1,
		//"Wrong length indicated. Expected 3, got %u", length - 1);
		return;
	}

	//proto_tree_add_item(param_tree, hf_sccp_segmentation_slr, tvb, 1, length - 1, ENC_LITTLE_ENDIAN);
}


static void
dissect_sccp_hop_counter_param(tvbuff_t *tvb, guint length)
{
	guint8 hops;

	hops = tvb_get_guint8(tvb, 0);
	//proto_tree_add_uint(tree, hf_sccp_hop_counter, tvb, 0, length, hops);
}

static void
dissect_sccp_importance_param(tvbuff_t *tvb, guint length)
{
	if (length != 1) {
		//proto_tree_add_expert_format(tree, pinfo, &ei_sccp_wrong_length, tvb, 0, length,
		//"Wrong length indicated. Expected 1, got %u", length);
		return;
	}

	//proto_tree_add_item(tree, hf_sccp_importance, tvb, 0, length, ENC_NA);
}


static void
dissect_sccp_unknown_param(tvbuff_t *tvb, guint8 type, guint length)
{
	//proto_tree_add_text(tree, tvb, 0, length, "Unknown parameter 0x%x (%u byte%s)",
	//type, length, plurality(length, "", "s"));
	printf("unknown parameter ");
}

static void
dissect_sccp_isni_param(tvbuff_t *tvb, guint length)
{
	guint8 ti;
	guint offset = 0;
	proto_item *param_item;
	proto_tree *param_tree;

	/* Create a subtree for ISNI Routing Control */
	//param_item = proto_tree_add_text(tree, tvb, offset, ANSI_ISNI_ROUTING_CONTROL_LENGTH,
	//"ISNI Routing Control");
	//param_tree = proto_item_add_subtree(param_item,
	//ett_sccp_ansi_isni_routing_control);

	//proto_tree_add_item(param_tree, hf_sccp_ansi_isni_mi, tvb, offset,
	//ANSI_ISNI_ROUTING_CONTROL_LENGTH, ENC_NA);

	//proto_tree_add_item(param_tree, hf_sccp_ansi_isni_iri, tvb, offset,
	//ANSI_ISNI_ROUTING_CONTROL_LENGTH, ENC_NA);

	ti = tvb_get_guint8(tvb, offset) & ANSI_ISNI_TI_MASK;
	//proto_tree_add_uint(param_tree, hf_sccp_ansi_isni_ti, tvb, offset,
	//ANSI_ISNI_ROUTING_CONTROL_LENGTH, ti);

	//proto_tree_add_item(param_tree, hf_sccp_ansi_isni_counter, tvb, offset,
	//ANSI_ISNI_ROUTING_CONTROL_LENGTH, ENC_NA);

	offset += ANSI_ISNI_ROUTING_CONTROL_LENGTH;

	if ((ti >> ANSI_ISNI_TI_SHIFT) == ANSI_ISNI_TYPE_1) {
		//proto_tree_add_uint(param_tree, hf_sccp_ansi_isni_netspec, tvb, offset,
		//ANSI_ISNI_ROUTING_CONTROL_LENGTH, ti);
		offset += ANSI_ISNI_ROUTING_CONTROL_LENGTH;
	}

	while (offset < length) {

		//proto_tree_add_item(tree, hf_sccp_ansi_isni_network, tvb, offset,
		//ANSI_NCM_LENGTH, ENC_NA);
		offset++;

		//proto_tree_add_item(tree, hf_sccp_ansi_isni_cluster, tvb, offset,
		//ANSI_NCM_LENGTH, ENC_NA);
		offset++;
	}

}


gboolean
proto_is_protocol_enabled(const protocol_t *protocol)
{
	return protocol->is_enabled;
}

static int
call_dissector_work(dissector_handle_t handle, tvbuff_t *tvb,
	gboolean add_proto_name, void *data)
{
	//packet_info *pinfo = pinfo_arg;
	const char  *saved_proto;
	guint16      saved_can_desegment;
	int          ret = 0;
	gint         saved_layer_names_len = 0;

	if (handle->protocol != NULL &&
		!proto_is_protocol_enabled(handle->protocol)) {
		/*
		* The protocol isn't enabled.
		*/
		return 0;
	}

	//saved_proto = pinfo->current_proto;
	//saved_can_desegment = pinfo->can_desegment;

	/*if (pinfo->layer_names != NULL)
	saved_layer_names_len = (gint)pinfo->layer_names->len;
	*/
	/*
	* can_desegment is set to 2 by anyone which offers the
	* desegmentation api/service.
	* Then everytime a subdissector is called it is decremented
	* by one.
	* Thus only the subdissector immediately on top of whoever
	* offers this service can use it.
	* We save the current value of "can_desegment" for the
	* benefit of TCP proxying dissectors such as SOCKS, so they
	* can restore it and allow the dissectors they call to use
	* the desegmentation service.
	*/
	//pinfo->saved_can_desegment = saved_can_desegment;
	//pinfo->can_desegment = saved_can_desegment - (saved_can_desegment>0);
	if (handle->protocol != NULL) {
		//pinfo->current_proto =
		//proto_get_protocol_short_name(handle->protocol);

		/*
		* Add the protocol name to the layers
		* if not told not to. Asn2wrs generated dissectors may be added multiple times otherwise.
		*/
		//if (add_proto_name) {
		//pinfo->curr_layer_num++;
		/*if (pinfo->layer_names) {
		if (pinfo->layer_names->len > 0)
		g_string_append(pinfo->layer_names, ":");
		g_string_append(pinfo->layer_names,
		proto_get_protocol_filter_name(proto_get_id(handle->protocol)));
		}*/
		//}
	}

	//if (pinfo->flags.in_error_pkt) {
	//	ret = call_dissector_work_error(handle, tvb, pinfo, tree, data);
	//}
	//else {
	//	/*
	//	* Just call the subdissector.
	//	*/
	//	ret = call_dissector_through_handle(handle, tvb, pinfo, tree, data);
	//}
	if (ret == 0) {
		/*
		* That dissector didn't accept the packet, so
		* remove its protocol's name from the list
		* of protocols.
		*/
		//if ((pinfo->layer_names != NULL) && (add_proto_name)) {
		//			g_string_truncate(pinfo->layer_names, saved_layer_names_len);
		//}
	}
	//pinfo->current_proto = saved_proto;
	//pinfo->can_desegment = saved_can_desegment;
	return ret;
}



int
call_dissector_with_data(dissector_handle_t handle, tvbuff_t *tvb,
	void *data)
{
	int ret = 0;

	//ret = call_dissector_only(handle, tvb, pinfo, tree, data);
	if (ret == 0) {
		/*
		* The protocol was disabled, or the dissector rejected
		* it.  Just dissect this packet as data.
		*/
		//g_assert(data_handle->protocol != NULL);
		call_dissector_work(data_handle, tvb, TRUE, NULL);
		return tvb_length(tvb);
	}
	return ret;
}


int
call_dissector(dissector_handle_t handle, tvbuff_t *tvb)
{
	return call_dissector_with_data(handle, tvb, NULL);
}


void call_tcap_dissector(dissector_handle_t handle, tvbuff_t* tvb) {

	requested_subdissector_handle = handle;

	//	try{
	//printf("this is try block");
	////dissect_tcap(tvb, pinfo, tree);
	//} CATCH_ALL{
	//requested_subdissector_handle = NULL;
	//RETHROW;
	//} ENDTRY;

	requested_subdissector_handle = NULL;

}




gboolean
dissector_try_uint_new(dissector_table_t sub_dissectors, const guint32 uint_val,
	tvbuff_t *tvb,
	const gboolean add_proto_name, void *data)
{
	dtbl_entry_t            *dtbl_entry;
	struct dissector_handle *handle = NULL;
	guint32                  saved_match_uint;
	int ret;

	dtbl_entry = find_uint_dtbl_entry(sub_dissectors, uint_val);
	if (dtbl_entry != NULL) {
		/*
		* Is there currently a dissector handle for this entry?
		*/
		//handle = dtbl_entry->current;
		if (handle == NULL) {
			/*
			* No - pretend this dissector didn't exist,
			* so that other dissectors might have a chance
			* to dissect this packet.
			*/
			return FALSE;
		}

		/*
		* Save the current value of "pinfo->match_uint",
		* set it to the uint_val that matched, call the
		* dissector, and restore "pinfo->match_uint".
		*/
		//saved_match_uint = pinfo->match_uint;
		//pinfo->match_uint = uint_val;
		//ret = call_dissector_work(handle, tvb, add_proto_name, data);
		//pinfo->match_uint = saved_match_uint;

		/*
		* If a new-style dissector returned 0, it means that
		* it didn't think this tvbuff represented a packet for
		* its protocol, and didn't dissect anything.
		*
		* Old-style dissectors can't reject the packet.
		*
		* 0 is also returned if the protocol wasn't enabled.
		*
		* If the packet was rejected, we return FALSE, so that
		* other dissectors might have a chance to dissect this
		* packet, otherwise we return TRUE.
		*/
		ret = 0;
		return ret != 0;
	}
	return FALSE;
}


gboolean
dissector_try_uint(dissector_table_t sub_dissectors, const guint32 uint_val,
	tvbuff_t *tvb)
{

	return dissector_try_uint_new(sub_dissectors, uint_val, tvb, TRUE, NULL);
}


gboolean
dissector_try_heuristic(heur_dissector_list_t sub_dissectors, tvbuff_t *tvb,
	void *data)
{
	gboolean           status;
	const char        *saved_proto;
	GSList            *entry = NULL;
	heur_dtbl_entry_t *hdtbl_entry;
	guint16            saved_can_desegment;
	gint               saved_layer_names_len = 0;

	/* can_desegment is set to 2 by anyone which offers this api/service.
	then everytime a subdissector is called it is decremented by one.
	thus only the subdissector immediately ontop of whoever offers this
	service can use it.
	We save the current value of "can_desegment" for the
	benefit of TCP proxying dissectors such as SOCKS, so they
	can restore it and allow the dissectors they call to use
	the desegmentation service.
	*/
	//saved_can_desegment = pinfo->can_desegment;
	//pinfo->saved_can_desegment = saved_can_desegment;
	//pinfo->can_desegment = saved_can_desegment - (saved_can_desegment>0);

	status = FALSE;
	//saved_proto = pinfo->current_proto;

	/*if (pinfo->layer_names != NULL)
	saved_layer_names_len = (gint)pinfo->layer_names->len;
	*/
	//for (entry = sub_dissectors; entry != NULL; entry = g_slist_next(entry)) {
	/* XXX - why set this now and above? */
	//pinfo->can_desegment = saved_can_desegment - (saved_can_desegment>0);
	hdtbl_entry = (heur_dtbl_entry_t *)entry->data;

	//if (hdtbl_entry->protocol != NULL &&
	//			(!proto_is_protocol_enabled(hdtbl_entry->protocol) || (hdtbl_entry->enabled == FALSE))) {
	//			/*
	//			* No - don't try this dissector.
	//			*/
	//			continue;
	//		}

	if (hdtbl_entry->protocol != NULL) {
		//pinfo->current_proto =
		//proto_get_protocol_short_name(hdtbl_entry->protocol);

		/*
		* Add the protocol name to the layers; we'll remove it
		* if the dissector fails.
		*/
		/*if (pinfo->layer_names) {
		if (pinfo->layer_names->len > 0)
		g_string_append(pinfo->layer_names, ":");
		g_string_append(pinfo->layer_names,
		proto_get_protocol_filter_name(proto_get_id(hdtbl_entry->protocol)));
		}*/
		/*}
		EP_CHECK_CANARY(("before calling heuristic dissector for protocol: %s",
		proto_get_protocol_filter_name(proto_get_id(hdtbl_entry->protocol))));*/
		if ((*hdtbl_entry->dissector)/*(tvb,  tree,data)*/) {
			//EP_CHECK_CANARY(("after heuristic dissector for protocol: %s has accepted and dissected packet",
			//				proto_get_protocol_filter_name(proto_get_id(hdtbl_entry->protocol))));
			status = TRUE;
			//break;
		}
		else {
			//EP_CHECK_CANARY(("after heuristic dissector for protocol: %s has returned false",
			//				proto_get_protocol_filter_name(proto_get_id(hdtbl_entry->protocol))));

			/*
			* That dissector didn't accept the packet, so
			* remove its protocol's name from the list
			* of protocols.
			*/
			//if (pinfo->layer_names != NULL) {
			//g_string_truncate(pinfo->layer_names, saved_layer_names_len);
			//}
		}
	}
	//pinfo->current_proto = saved_proto;
	//pinfo->can_desegment = saved_can_desegment;
	return status;
}


/* This function is used for both data and long data (ITU only) parameters */
static void
dissect_sccp_data_param(tvbuff_t *tvb)
{
	guint8 ssn = INVALID_SSN;
	guint8 other_ssn = INVALID_SSN;
	const mtp3_addr_pc_t *dpc = NULL;
	const mtp3_addr_pc_t *opc = NULL;

	/* if ((trace_sccp) && (assoc && assoc != &no_assoc)) {
	pinfo->sccp_info = assoc->curr_msg;
	}
	else {
	pinfo->sccp_info = NULL;
	} */

	/*if (assoc) {
	switch (pinfo->p2p_dir) {
	case P2P_DIR_SENT:
	ssn = assoc->calling_ssn;
	other_ssn = assoc->called_ssn;
	dpc = (const mtp3_addr_pc_t*)pinfo->dst.data;
	opc = (const mtp3_addr_pc_t*)pinfo->src.data;
	break;
	case P2P_DIR_RECV:
	ssn = assoc->called_ssn;
	other_ssn = assoc->calling_ssn;
	dpc = (const mtp3_addr_pc_t*)pinfo->src.data;
	opc = (const mtp3_addr_pc_t*)pinfo->dst.data;
	break;
	default:
	ssn = assoc->called_ssn;
	other_ssn = assoc->calling_ssn;
	dpc = (const mtp3_addr_pc_t*)pinfo->dst.data;
	opc = (const mtp3_addr_pc_t*)pinfo->src.data;
	break;
	}
	}
	*/



	//if (num_sccp_users) {
	//	guint i;
	//	dissector_handle_t handle = NULL;
	//	gboolean uses_tcap = FALSE;

	//	for (i = 0; i < num_sccp_users; i++) {
	//		sccp_user_t *u = &(sccp_users[i]);

	//		if (!dpc || dpc->ni != u->ni) continue;

	//		/* if (value_is_in_range(u->called_ssn, ssn) && value_is_in_range(u->called_pc, dpc->pc)) {
	//		handle = *(u->handlep);
	//		uses_tcap = u->uses_tcap;
	//		break;
	//		}
	//		else if (value_is_in_range(u->called_ssn, other_ssn) && opc && value_is_in_range(u->called_pc, opc->pc)) {
	//		handle = *(u->handlep);
	//		uses_tcap = u->uses_tcap;
	//		break;
	//		} */
	//	}

	//	if (handle) {
	//		if (uses_tcap) {
	//			call_tcap_dissector(handle, tvb);
	//		}
	//		else {
	//			call_dissector(handle, tvb);
	//		}
	//		return;
	//	}

	//}

	//if ((ssn != INVALID_SSN) && dissector_try_uint(sccp_ssn_dissector_table, ssn, tvb)) {
	//	return;
	//}

	//if ((other_ssn != INVALID_SSN) && dissector_try_uint(sccp_ssn_dissector_table, other_ssn, tvb)) {
	//	return;
	//}

	///* try heuristic subdissector list to see if there are any takers */
	//if (dissector_try_heuristic(heur_subdissector_list, tvb, NULL)) {
	//	return;
	//}

	///* try user default subdissector */
	//if (default_handle) {
	//	call_dissector(default_handle, tvb);
	//	return;
	//}

	///* No sub-dissection occurred, treat it as raw data */
	//call_dissector(data_handle, tvb);

}


static guint16
dissect_sccp_parameter(tvbuff_t *tvb,
	guint8 parameter_type, guint16 offset,
	guint16 parameter_length, SS7_target* target)
{
	tvbuff_t *parameter_tvb = (tvbuff_t *)malloc(sizeof(tvbuff_t *));

	switch (parameter_type) {
	case PARAMETER_CALLED_PARTY_ADDRESS:
	case PARAMETER_CALLING_PARTY_ADDRESS:
	case PARAMETER_DATA:
	case PARAMETER_LONG_DATA:
	case PARAMETER_SOURCE_LOCAL_REFERENCE:
	case PARAMETER_DESTINATION_LOCAL_REFERENCE:
	case PARAMETER_RELEASE_CAUSE:
	case PARAMETER_RETURN_CAUSE:
	case PARAMETER_RESET_CAUSE:
	case PARAMETER_ERROR_CAUSE:
	case PARAMETER_REFUSAL_CAUSE:
	case PARAMETER_CLASS:

		/*  These parameters must be dissected even if !sccp_tree (so that
		*  assoc information can be created).
		*/
		break;

	default:
		return(parameter_length);

	}

	switch (parameter_type) {

             //parameter_tvb = tvb_new_subset(tvb, offset, parameter_length, parameter_length);

	case PARAMETER_CALLED_PARTY_ADDRESS:
		printf(" %s", "PARAMETER_CALLED_PARTY_ADDRESS");
		dissect_sccp_called_param(tvb, parameter_length, target, offset);
		break;

	case PARAMETER_CALLING_PARTY_ADDRESS:
		dissect_sccp_calling_param(tvb, parameter_length, target, offset);
		break;


	case PARAMETER_DESTINATION_LOCAL_REFERENCE:
//dissect_sccp_dlr_param(parameter_tvb, parameter_length, );
		break;

	case PARAMETER_SOURCE_LOCAL_REFERENCE:
		dissect_sccp_slr_param(parameter_tvb, parameter_length);
		break;

	case PARAMETER_CLASS:
		dissect_sccp_class_param(tvb, parameter_length, offset);
		break;

		/*case PARAMETER_SEGMENTING_REASSEMBLING:
		dissect_sccp_segmenting_reassembling_param(parameter_tvb, sccp_tree,
		parameter_length);
		break;*/

	case PARAMETER_RECEIVE_SEQUENCE_NUMBER:
		dissect_sccp_receive_sequence_number_param(parameter_tvb,
			parameter_length);
		break;


	case PARAMETER_SEQUENCING_SEGMENTING:
		dissect_sccp_sequencing_segmenting_param(parameter_tvb,
			parameter_length);
		break;

	case PARAMETER_CREDIT:
		dissect_sccp_credit_param(parameter_tvb, parameter_length);
		break;

	case PARAMETER_RELEASE_CAUSE:
		dissect_sccp_release_cause_param(parameter_tvb, parameter_length);
		break;


	case PARAMETER_RETURN_CAUSE:
		dissect_sccp_return_cause_param(parameter_tvb, parameter_length);
		break;


	case PARAMETER_RESET_CAUSE:
		dissect_sccp_reset_cause_param(parameter_tvb, parameter_length);
		break;

	case PARAMETER_ERROR_CAUSE:
		dissect_sccp_error_cause_param(parameter_tvb, parameter_length);
		break;

	case PARAMETER_REFUSAL_CAUSE:
		dissect_sccp_refusal_cause_param(parameter_tvb, parameter_length);
		break;


	case PARAMETER_DATA:
		dissect_sccp_data_param(parameter_tvb);

		// TODO? Re-adjust length of SCCP item since it may be sub-dissected
		/* sccp_length = proto_item_get_len(sccp_item);
		sccp_length -= parameter_length;
		proto_item_set_len(sccp_item, sccp_length);*/

		break;

	case PARAMETER_SEGMENTATION:
		dissect_sccp_segmentation_param(parameter_tvb, parameter_length);
		break;


	case PARAMETER_HOP_COUNTER:
		dissect_sccp_hop_counter_param(parameter_tvb, parameter_length);
		break;


	case PARAMETER_IMPORTANCE:
		if (decode_mtp3_standard != ANSI_STANDARD)
			dissect_sccp_importance_param(parameter_tvb, parameter_length);
		else
			dissect_sccp_unknown_param(parameter_tvb, parameter_type,
				parameter_length);
		break;

	case PARAMETER_LONG_DATA:
		dissect_sccp_data_param(parameter_tvb);
		break;


	case PARAMETER_ISNI:
		if (decode_mtp3_standard != ANSI_STANDARD)
			dissect_sccp_unknown_param(parameter_tvb, parameter_type,
				parameter_length);
		else
			dissect_sccp_isni_param(parameter_tvb, parameter_length);
		break;


	default:
		dissect_sccp_unknown_param(parameter_tvb, parameter_type,
			parameter_length);
		break;
	}


	return(parameter_length);
}





/* proto_item *
proto_tree_add_uint(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
gint length, guint32 value)
{
proto_item	  *pi = NULL;
header_field_info *hfinfo;

//	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

switch (hfinfo->type) {
case FT_UINT8:
case FT_UINT16:
case FT_UINT24:
case FT_UINT32:
case FT_FRAMENUM:
pi = proto_tree_add_pi(tree, hfinfo, tvb, start, &length);
//proto_tree_set_uint(PNODE_FINFO(pi), value);
break;

default:
DISSECTOR_ASSERT_NOT_REACHED();
}

return pi;
} */

static inline int
validate_offset(const tvbuff_t *tvb, const guint abs_offset)
{
	int exception = 0;

	/* if (G_LIKELY(abs_offset <= tvb->length))
	exception = 0;
	else if (abs_offset <= tvb->reported_length)
	exception = BoundsError;
	else {
	if (tvb->flags & TVBUFF_FRAGMENT)
	exception = FragmentBoundsError;
	else
	exception = ReportedBoundsError;
	}*/

	return exception;
}

guint16
tvb_get_letohs(tvbuff_t *tvb, const gint offset)
{
	const guint8 *ptr;

	ptr = fast_ensure_contiguous(tvb, offset, sizeof(guint16));
	//return pletohs(ptr);
	return 1;
}

static guint16
dissect_sccp_variable_parameter(tvbuff_t *tvb,

	guint8 parameter_type, guint16 offset, SS7_target* target)
{
	guint16     parameter_length;
	guint8      length_length;
	proto_item *pi;

	if (parameter_type != PARAMETER_LONG_DATA) {
		parameter_length = tvb_get_guint8(tvb, offset);
		length_length = PARAMETER_LENGTH_LENGTH;
	}
	else {
		/* Long data parameter has 16 bit length */
		parameter_length = tvb_get_letohs(tvb, offset);
		length_length = PARAMETER_LONG_DATA_LENGTH_LENGTH;
	}

	//pi = proto_tree_add_uint_format(sccp_tree, hf_sccp_param_length, tvb, offset,
	//length_length, parameter_length, "%s length: %d",
	//val_to_str(parameter_type, sccp_parameter_values,
	//	"Unknown: %d"),
	//parameter_length);
	//if (!sccp_show_length) {
	/* The user doesn't want to see it... */
	//PROTO_ITEM_SET_HIDDEN(pi);
	//}

	offset += length_length;

	dissect_sccp_parameter(tvb, parameter_type, offset,
		parameter_length, target);

	return(parameter_length + length_length);
}

static fragment_head *
lookup_fd_head(reassembly_table *table,
	const guint32 id, const void *data, gpointer *orig_keyp)
{
	gpointer key;
	gpointer value;

	/* Create key to search hash with */
	//key = table->temporary_key_func(pinfo, id, data);

	/*
	* Look up the reassembly in the fragment table.
	*/
	if (!g_hash_table_lookup_extended(table->fragment_table, key, orig_keyp,
		&value))
		value = NULL;
	/* Free the key */
	// revisioning required
	//table->free_temporary_key_func(key);

	return (fragment_head *)value;
}

static fragment_head *new_head(const guint32 flags)
{
	fragment_head *fd_head = NULL;
	/* If head/first structure in list only holds no other data than
	* 'datalen' then we don't have to change the head of the list
	* even if we want to keep it sorted
	*/
	//	fd_head = g_slice_new0(fragment_head);

	fd_head->flags = flags;
	return fd_head;
}

static gpointer
insert_fd_head(reassembly_table *table, fragment_head *fd_head,
	const guint32 id, const void *data)
{
	gpointer key = 0;

	/*
	* We're going to use the key to insert the fragment,
	* so make a persistent version of it.
	*/
	//key = table->persistent_key_func(pinfo, id, data);
	g_hash_table_insert(table->fragment_table, key, fd_head);
	return key;
}



void
tvb_check_offset_length(const tvbuff_t *tvb,
	const gint offset, gint const length_val,
	guint *offset_ptr, guint *length_ptr)
{
	//	check_offset_length(tvb, offset, length_val, offset_ptr, length_ptr);
}

static guint
subset_offset(const tvbuff_t *tvb, const guint counter)
{
	const struct tvb_subset *subset_tvb = (const struct tvb_subset *) tvb;
	const tvbuff_t *member = subset_tvb->subset.tvb;

	return tvb_offset_from_real_beginning_counter(member, counter + subset_tvb->subset.offset);
}

static void
check_offset_length(const tvbuff_t *tvb,
	const gint offset, gint const length_val,
	guint *offset_ptr, guint *length_ptr)
{
	int exception;

	exception = check_offset_length_no_exception(tvb, offset, length_val, offset_ptr, length_ptr);
	if (exception)
		THROW(exception);
}


void *
tvb_memcpy(tvbuff_t *tvb, void *target, const gint offset, size_t length)
{
	guint	abs_offset, abs_length;

	DISSECTOR_ASSERT(tvb && tvb->initialized);

	/*
	* XXX - we should eliminate the "length = -1 means 'to the end
	* of the tvbuff'" convention, and use other means to achieve
	* that; this would let us eliminate a bunch of checks for
	* negative lengths in cases where the protocol has a 32-bit
	* length field.
	*
	* Allowing -1 but throwing an assertion on other negative
	* lengths is a bit more work with the length being a size_t;
	* instead, we check for a length <= 2^31-1.
	*/
	DISSECTOR_ASSERT(length <= 0x7FFFFFFF);
	check_offset_length(tvb, offset, (gint)length, &abs_offset, &abs_length);

	if (tvb->real_data) {
		return memcpy(target, tvb->real_data + abs_offset, abs_length);
	}

	if (tvb->ops->tvb_memcpy)
		return tvb->ops->tvb_memcpy(tvb, target, abs_offset, abs_length);

	/* XXX, fallback to slower method */

	DISSECTOR_ASSERT_NOT_REACHED();
	return NULL;
}


static void *
subset_memcpy(tvbuff_t *tvb, void *target, guint abs_offset, guint abs_length)
{
	struct tvb_subset *subset_tvb = (struct tvb_subset *) tvb;

	return tvb_memcpy(subset_tvb->subset.tvb, target, subset_tvb->subset.offset + abs_offset, abs_length);
}


static gint
tvb_find_guint8_generic(tvbuff_t *tvb, guint abs_offset, guint limit, guint8 needle)
{
	const guint8 *ptr;
	const guint8 *result;

	ptr = tvb_get_ptr(tvb, abs_offset, limit);

	result = (const guint8 *)memchr(ptr, needle, limit);
	if (!result)
		return -1;

	return (gint)((result - ptr) + abs_offset);
}



gint
tvb_find_guint8(tvbuff_t *tvb, const gint offset, const gint maxlength, const guint8 needle)
{
	const guint8 *result;
	guint	      abs_offset;
	guint	      tvbufflen;
	guint	      limit;

	DISSECTOR_ASSERT(tvb && tvb->initialized);

	check_offset_length(tvb, offset, -1, &abs_offset, &tvbufflen);

	/* Only search to end of tvbuff, w/o throwing exception. */
	if (maxlength == -1) {
		/* No maximum length specified; search to end of tvbuff. */
		limit = tvbufflen;
	}
	else if (tvbufflen < (guint)maxlength) {
		/* Maximum length goes past end of tvbuff; search to end
		of tvbuff. */
		limit = tvbufflen;
	}
	else {
		/* Maximum length doesn't go past end of tvbuff; search
		to that value. */
		limit = maxlength;
	}

	/* If we have real data, perform our search now. */
	if (tvb->real_data) {
		result = (const guint8 *)memchr(tvb->real_data + abs_offset, needle, limit);
		if (result == NULL) {
			return -1;
		}
		else {
			return (gint)(result - tvb->real_data);
		}
	}

	if (tvb->ops->tvb_find_guint8)
		return tvb->ops->tvb_find_guint8(tvb, abs_offset, limit, needle);

	return tvb_find_guint8_generic(tvb, offset, limit, needle);
}

static gint
subset_find_guint8(tvbuff_t *tvb, guint abs_offset, guint limit, guint8 needle)
{
	struct tvb_subset *subset_tvb = (struct tvb_subset *) tvb;

	return tvb_find_guint8(subset_tvb->subset.tvb, subset_tvb->subset.offset + abs_offset, limit, needle);
}



static const guint8*
guint8_pbrk(const guint8* haystack, size_t haystacklen, const guint8 *needles, guchar *found_needle)
{
	gchar         tmp[256] = { 0 };
	const guint8 *haystack_end;

	while (*needles)
		tmp[*needles++] = 1;

	haystack_end = haystack + haystacklen;
	while (haystack < haystack_end) {
		if (tmp[*haystack]) {
			if (found_needle)
				*found_needle = *haystack;
			return haystack;
		}
		haystack++;
	}

	return NULL;
}

static gint
tvb_pbrk_guint8_generic(tvbuff_t *tvb, guint abs_offset, guint limit, const guint8 *needles, guchar *found_needle)
{
	const guint8 *ptr;
	const guint8 *result;

	ptr = tvb_get_ptr(tvb, abs_offset, limit);

	result = guint8_pbrk(ptr, limit, needles, found_needle);
	if (!result)
		return -1;

	return (gint)((result - ptr) + abs_offset);
}




gint
tvb_pbrk_guint8(tvbuff_t *tvb, const gint offset, const gint maxlength, const guint8 *needles, guchar *found_needle)
{
	const guint8 *result;
	guint	      abs_offset;
	guint	      tvbufflen;
	guint	      limit;

	DISSECTOR_ASSERT(tvb && tvb->initialized);

	check_offset_length(tvb, offset, -1, &abs_offset, &tvbufflen);

	/* Only search to end of tvbuff, w/o throwing exception. */
	if (maxlength == -1) {
		/* No maximum length specified; search to end of tvbuff. */
		limit = tvbufflen;
	}
	else if (tvbufflen < (guint)maxlength) {
		/* Maximum length goes past end of tvbuff; search to end
		of tvbuff. */
		limit = tvbufflen;
	}
	else {
		/* Maximum length doesn't go past end of tvbuff; search
		to that value. */
		limit = maxlength;
	}

	/* If we have real data, perform our search now. */
	if (tvb->real_data) {
		result = guint8_pbrk(tvb->real_data + abs_offset, limit, needles, found_needle);
		if (result == NULL) {
			return -1;
		}
		else {
			return (gint)(result - tvb->real_data);
		}
	}

	if (tvb->ops->tvb_pbrk_guint8)
		return tvb->ops->tvb_pbrk_guint8(tvb, abs_offset, limit, needles, found_needle);

	return tvb_pbrk_guint8_generic(tvb, abs_offset, limit, needles, found_needle);
}

static gint
subset_pbrk_guint8(tvbuff_t *tvb, guint abs_offset, guint limit, const guint8 *needles, guchar *found_needle)
{
	struct tvb_subset *subset_tvb = (struct tvb_subset *) tvb;

	return tvb_pbrk_guint8(subset_tvb->subset.tvb, subset_tvb->subset.offset + abs_offset, limit, needles, found_needle);
}


static void
real_free(tvbuff_t *tvb)
{
	struct tvb_real *real_tvb = (struct tvb_real *) tvb;

	if (real_tvb->free_cb) {
		/*
		* XXX - do this with a union?
		*/
		real_tvb->free_cb((gpointer)tvb->real_data);
	}
}


static const struct tvb_ops tvb_real_ops = {
	sizeof(struct tvb_real), /* size */

	real_free,            /* free */
						  //real_offset,          /* offset */
						  NULL,                 /* get_ptr */
						  NULL,                 /* memcpy */
						  NULL,                 /* find_guint8 */
						  NULL,                 /* pbrk_guint8 */
												// NULL,                /* clone */
};

tvbuff_t *
tvb_new(const struct tvb_ops *ops)
{
	tvbuff_t *tvb = NULL;
	gsize     size = ops->tvb_size ? ops->tvb_size : sizeof(*tvb);

	//g_assert(size >= sizeof(*tvb));

	//tvb = (tvbuff_t *)g_slice_alloc(size);

	tvb->next = NULL;
	tvb->ops = ops;
	tvb->initialized = FALSE;
	tvb->flags = 0;
	tvb->length = 0;
	tvb->reported_length = 0;
	tvb->real_data = NULL;
	tvb->raw_offset = -1;
	tvb->ds_tvb = NULL;

	return tvb;
}


tvbuff_t *
tvb_new_real_data(const guint8* data, const guint length, const gint reported_length)
{
	tvbuff_t *tvb;
	struct tvb_real *real_tvb;

	THROW_ON(reported_length < -1, ReportedBoundsError);

	tvb = tvb_new(&tvb_real_ops);

	tvb->real_data = data;
	tvb->length = length;
	tvb->reported_length = reported_length;
	tvb->initialized = TRUE;

	/*
	* This is the top-level real tvbuff for this data source,
	* so its data source tvbuff is itself.
	*/
	tvb->ds_tvb = tvb;

	real_tvb = (struct tvb_real *) tvb;
	real_tvb->free_cb = NULL;

	return tvb;
}


static tvbuff_t *
tvb_generic_clone_offset_len(tvbuff_t *tvb, guint offset, guint len)
{
	tvbuff_t *cloned_tvb;

	guint8 *data = NULL;
	//guint8 *data = (guint8 *)g_malloc(len)

	tvb_memcpy(tvb, data, offset, len);

	cloned_tvb = tvb_new_real_data(data, len, len);
	//tvb_set_free_cb(cloned_tvb, g_free);

	return cloned_tvb;
}


tvbuff_t *
tvb_clone_offset_len(tvbuff_t *tvb, guint offset, guint len)
{
	if (tvb->ops->tvb_clone) {
		tvbuff_t *cloned_tvb;

		cloned_tvb = tvb->ops->tvb_clone(tvb, offset, len);
		if (cloned_tvb)
			return cloned_tvb;
	}

	return tvb_generic_clone_offset_len(tvb, offset, len);
}

static tvbuff_t *
subset_clone(tvbuff_t *tvb, guint abs_offset, guint abs_length)
{
	struct tvb_subset *subset_tvb = (struct tvb_subset *) tvb;

	return tvb_clone_offset_len(subset_tvb->subset.tvb, subset_tvb->subset.offset + abs_offset, abs_length);
}


static const guint8 *
subset_get_ptr(tvbuff_t *tvb, guint abs_offset, guint abs_length)
{
	struct tvb_subset *subset_tvb = (struct tvb_subset *) tvb;

	return tvb_get_ptr(subset_tvb->subset.tvb, subset_tvb->subset.offset + abs_offset, abs_length);
}


static const struct tvb_ops tvb_subset_ops = {
	sizeof(struct tvb_subset), /* size */

							   //subset_get_ptr,       /* get_ptr */
							   //subset_memcpy,        /* memcpy */
							   //subset_find_guint8,   /* find_guint8 */
							   //subset_pbrk_guint8,   /* pbrk_guint8 */
							   //subset_clone,         /* clone */
};

static tvbuff_t *
tvb_new_with_subset(tvbuff_t *backing, const gint reported_length,
	const guint subset_tvb_offset, const guint subset_tvb_length)
{
	tvbuff_t *tvb = tvb_new(&tvb_subset_ops);
	struct tvb_subset *subset_tvb = (struct tvb_subset *) tvb;

	subset_tvb->subset.offset = subset_tvb_offset;
	subset_tvb->subset.length = subset_tvb_length;

	subset_tvb->subset.tvb = backing;
	tvb->length = subset_tvb_length;
	tvb->flags = backing->flags;

	if (reported_length == -1) {
		tvb->reported_length = backing->reported_length - subset_tvb_offset;
	}
	else {
		tvb->reported_length = reported_length;
	}
	tvb->initialized = TRUE;

	/* Optimization. If the backing buffer has a pointer to contiguous, real data,
	* then we can point directly to our starting offset in that buffer */
	if (backing->real_data != NULL) {
		tvb->real_data = backing->real_data + subset_tvb_offset;
	}

	/*
	* The top-level data source of this tvbuff is the top-level
	* data source of its parent.
	*/
	tvb->ds_tvb = backing->ds_tvb;

	return tvb;
}

void
tvb_add_to_chain(tvbuff_t *parent, tvbuff_t *child)
{
	tvbuff_t *tmp = child;

	DISSECTOR_ASSERT(parent);
	DISSECTOR_ASSERT(child);

	while (child) {
		tmp = child;
		child = child->next;

		tmp->next = parent->next;
		parent->next = tmp;
	}
}


tvbuff_t *
tvb_new_subset_remaining(tvbuff_t *backing, const gint backing_offset)
{
	tvbuff_t *tvb;
	guint	  subset_tvb_offset;
	guint	  subset_tvb_length;

	tvb_check_offset_length(backing, backing_offset, -1 /* backing_length */,
		&subset_tvb_offset,
		&subset_tvb_length);

	tvb = tvb_new_with_subset(backing, -1 /* reported_length */,
		subset_tvb_offset, subset_tvb_length);

	tvb_add_to_chain(backing, tvb);

	return tvb;
}

static void
LINK_FRAG(fragment_head *fd_head, fragment_item *fd)
{
	fragment_item *fd_i;

	/* add fragment to list, keep list sorted */
	for (fd_i = fd_head; fd_i->next; fd_i = fd_i->next) {
		if (fd->offset < fd_i->next->offset)
			break;
	}
	fd->next = fd_i->next;
	fd_i->next = fd;
}

gint
tvb_memeql(tvbuff_t *tvb, const gint offset, const guint8 *str, size_t size)
{
	const guint8 *ptr;

	ptr = ensure_contiguous_no_exception(tvb, offset, (gint)size, NULL);

	if (ptr) {
		int cmp = memcmp(ptr, str, size);

		/*
		* Return 0 if equal, -1 otherwise.
		*/
		return (cmp == 0 ? 0 : -1);
	}
	else {
		/*
		* Not enough characters in the tvbuff to match the
		* string.
		*/
		return -1;
	}
}









static guint
real_offset(const tvbuff_t *tvb /*_U_*/, const guint counter)
{
	return counter;
}










void
tvb_set_free_cb(tvbuff_t *tvb, const tvbuff_free_cb_t func)
{
	struct tvb_real *real_tvb = (struct tvb_real *) tvb;

	DISSECTOR_ASSERT(tvb);
	DISSECTOR_ASSERT(tvb->ops == &tvb_real_ops);
	real_tvb->free_cb = func;
}


static void
tvb_free_internal(tvbuff_t *tvb)
{
	gsize     size;

	DISSECTOR_ASSERT(tvb);

	if (tvb->ops->tvb_free)
		tvb->ops->tvb_free(tvb);

	size = (tvb->ops->tvb_size) ? tvb->ops->tvb_size : sizeof(*tvb);

	//g_slice_free1(size, tvb);
}


void
tvb_free_chain(tvbuff_t  *tvb)
{
	tvbuff_t *next_tvb;
	DISSECTOR_ASSERT(tvb);
	while (tvb) {
		next_tvb = tvb->next;
		tvb_free_internal(tvb);
		tvb = next_tvb;
	}
}


void
tvb_free(tvbuff_t *tvb)
{
	tvb_free_chain(tvb);
}

static void
fragment_defragment_and_free(fragment_head *fd_head)
{
	fragment_item *fd_i = NULL;
	fragment_item *last_fd = NULL;
	guint32  dfpos = 0, size = 0;
	tvbuff_t *old_tvb_data = NULL;
	guint8 *data = NULL;

	for (fd_i = fd_head->next; fd_i; fd_i = fd_i->next) {
		if (!last_fd || last_fd->offset != fd_i->offset) {
			size += fd_i->len;
		}
		last_fd = fd_i;
	}

	/* store old data in case the fd_i->data pointers refer to it */
	old_tvb_data = fd_head->tvb_data;
	//data = (guint8 *)g_malloc(size);
	fd_head->tvb_data = tvb_new_real_data(data, size, size);
	//tvb_set_free_cb(fd_head->tvb_data, g_free);
	fd_head->len = size;		/* record size for caller	*/

								/* add all data fragments */
	last_fd = NULL;
	for (fd_i = fd_head->next; fd_i; fd_i = fd_i->next) {
		if (fd_i->len) {
			if (!last_fd || last_fd->offset != fd_i->offset) {
				/* First fragment or in-sequence fragment */
				memcpy(data + dfpos, tvb_get_ptr(fd_i->tvb_data, 0, fd_i->len), fd_i->len);
				dfpos += fd_i->len;
			}
			else {
				/* duplicate/retransmission/overlap */
				fd_i->flags |= FD_OVERLAP;
				fd_head->flags |= FD_OVERLAP;
				if (last_fd->len != fd_i->len
					|| tvb_memeql(last_fd->tvb_data, 0, tvb_get_ptr(fd_i->tvb_data, 0, last_fd->len), last_fd->len)) {
					fd_i->flags |= FD_OVERLAPCONFLICT;
					fd_head->flags |= FD_OVERLAPCONFLICT;
				}
			}
		}
		last_fd = fd_i;
	}

	/* we have defragmented the pdu, now free all fragments*/
	for (fd_i = fd_head->next; fd_i; fd_i = fd_i->next) {
		if (fd_i->flags & FD_SUBSET_TVB)
			fd_i->flags &= ~FD_SUBSET_TVB;
		else if (fd_i->tvb_data)
tvb_free(fd_i->tvb_data);
		fd_i->tvb_data = NULL;
	}
	if (old_tvb_data)
		tvb_free(old_tvb_data);

	/* mark this packet as defragmented.
	* allows us to skip any trailing fragments.
	*/
	fd_head->flags |= FD_DEFRAGMENTED;
	//fd_head->reassembled_in = pinfo->fd->num;
}


static gboolean
fragment_add_seq_work(fragment_head *fd_head, tvbuff_t *tvb, const int offset,
	const guint32 frag_number,
	const guint32 frag_data_len, const gboolean more_frags)
{
	fragment_item *fd = NULL;
	fragment_item *fd_i;
	fragment_item *last_fd;
	guint32 max, dfpos;
	guint32 frag_number_work;

	/* Enables the use of fragment sequence numbers, which do not start with 0 */
	frag_number_work = frag_number;
	if (fd_head->fragment_nr_offset != 0)
		if (frag_number_work >= fd_head->fragment_nr_offset)
			frag_number_work = frag_number - fd_head->fragment_nr_offset;

	/* if the partial reassembly flag has been set, and we are extending
	* the pdu, un-reassemble the pdu. This means pointing old fds to malloc'ed data.
	*/
	if (fd_head->flags & FD_DEFRAGMENTED && frag_number_work >= fd_head->datalen &&
		fd_head->flags & FD_PARTIAL_REASSEMBLY) {
		guint32 lastdfpos = 0;
		dfpos = 0;
		for (fd_i = fd_head->next; fd_i; fd_i = fd_i->next) {
			if (!fd_i->tvb_data) {
				if (fd_i->flags & FD_OVERLAP) {
					/* this is a duplicate of the previous
					* fragment. */
					fd_i->tvb_data = tvb_new_subset_remaining(fd_head->tvb_data, lastdfpos);
				}
				else {
					fd_i->tvb_data = tvb_new_subset_remaining(fd_head->tvb_data, dfpos);
					lastdfpos = dfpos;
					dfpos += fd_i->len;
				}
				fd_i->flags |= FD_SUBSET_TVB;
			}
			fd_i->flags &= (~FD_TOOLONGFRAGMENT) & (~FD_MULTIPLETAILS);
		}
		fd_head->flags &= ~(FD_DEFRAGMENTED | FD_PARTIAL_REASSEMBLY | FD_DATALEN_SET);
		fd_head->flags &= (~FD_TOOLONGFRAGMENT) & (~FD_MULTIPLETAILS);
		fd_head->datalen = 0;
		fd_head->reassembled_in = 0;
	}


	/* create new fd describing this fragment */
	fd = g_slice_new(fragment_item)
		fd->next = NULL;
	fd->flags = 0;
	//fd->frame = pinfo->fd->num;
	fd->offset = frag_number_work;
	fd->len = frag_data_len;
	fd->tvb_data = NULL;
	fd->error = NULL;

	if (!more_frags) {
		/*
		* This is the tail fragment in the sequence.
		*/
		if (fd_head->flags&FD_DATALEN_SET) {
			/* ok we have already seen other tails for this packet
			* it might be a duplicate.
			*/
			if (fd_head->datalen != fd->offset) {
				/* Oops, this tail indicates a different packet
				* len than the previous ones. Something's wrong.
				*/
				fd->flags |= FD_MULTIPLETAILS;
				fd_head->flags |= FD_MULTIPLETAILS;
			}
		}
		else {
			/* this was the first tail fragment, now we know the
			* sequence number of that fragment (which is NOT
			* the length of the packet!)
			*/
			fd_head->datalen = fd->offset;
			fd_head->flags |= FD_DATALEN_SET;
		}
	}

	/* If the packet is already defragmented, this MUST be an overlap.
	* The entire defragmented packet is in fd_head->data
	* Even if we have previously defragmented this packet, we still check
	* check it. Someone might play overlap and TTL games.
	*/
	if (fd_head->flags & FD_DEFRAGMENTED) {
		fd->flags |= FD_OVERLAP;
		fd_head->flags |= FD_OVERLAP;

		/* make sure it's not past the end */
		if (fd->offset > fd_head->datalen) {
			/* new fragment comes after the end */
			fd->flags |= FD_TOOLONGFRAGMENT;
			fd_head->flags |= FD_TOOLONGFRAGMENT;
			LINK_FRAG(fd_head, fd);
			return TRUE;
		}
		/* make sure it doesn't conflict with previous data */
		dfpos = 0;
		last_fd = NULL;
		for (fd_i = fd_head->next; fd_i && (fd_i->offset != fd->offset); fd_i = fd_i->next) {
			if (!last_fd || last_fd->offset != fd_i->offset) {
				dfpos += fd_i->len;
			}
			last_fd = fd_i;
		}
		if (fd_i) {
			/* new fragment overlaps existing fragment */
			if (fd_i->len != fd->len) {
				/*
				* They have different lengths; this
				* is definitely a conflict.
				*/
				fd->flags |= FD_OVERLAPCONFLICT;
				fd_head->flags |= FD_OVERLAPCONFLICT;
				LINK_FRAG(fd_head, fd);
				return TRUE;
			}
			DISSECTOR_ASSERT(fd_head->len >= dfpos + fd->len);
			if (tvb_memeql(fd_head->tvb_data, dfpos,
				tvb_get_ptr(tvb, offset, fd->len), fd->len)) {
				/*
				* They have the same length, but the
				* data isn't the same.
				*/
				fd->flags |= FD_OVERLAPCONFLICT;
				fd_head->flags |= FD_OVERLAPCONFLICT;
				LINK_FRAG(fd_head, fd);
				return TRUE;
			}
			/* it was just an overlap, link it and return */
			LINK_FRAG(fd_head, fd);
			return TRUE;
		}
		else {
			/*
			* New fragment doesn't overlap an existing
			* fragment - there was presumably a gap in
			* the sequence number space.
			*
			* XXX - what should we do here?  Is it always
			* the case that there are no gaps, or are there
			* protcols using sequence numbers where there
			* can be gaps?
			*
			* If the former, the check below for having
			* received all the fragments should check for
			* holes in the sequence number space and for the
			* first sequence number being 0.  If we do that,
			* the only way we can get here is if this fragment
			* is past the end of the sequence number space -
			* but the check for "fd->offset > fd_head->datalen"
			* would have caught that above, so it can't happen.
			*
			* If the latter, we don't have a good way of
			* knowing whether reassembly is complete if we
			* get packet out of order such that the "last"
			* fragment doesn't show up last - but, unless
			* in-order reliable delivery of fragments is
			* guaranteed, an implementation of the protocol
			* has no way of knowing whether reassembly is
			* complete, either.
			*
			* For now, we just link the fragment in and
			* return.
			*/
			LINK_FRAG(fd_head, fd);
			return TRUE;
		}
	}

	/* If we have reached this point, the packet is not defragmented yet.
	* Save all payload in a buffer until we can defragment.
	* XXX - what if we didn't capture the entire fragment due
	* to a too-short snapshot length?
	*/
	/* check len, there may be a fragment with 0 len, that is actually the tail */
	if (fd->len) {
		fd->tvb_data = tvb_clone_offset_len(tvb, offset, fd->len);
	}
	LINK_FRAG(fd_head, fd);


	if (!(fd_head->flags & FD_DATALEN_SET)) {
		/* if we dont know the sequence number of the last fragment,
		* there are definitely still missing packets. Cheaper than
		* the check below.
		*/
		return FALSE;
	}


	/* check if we have received the entire fragment
	* this is easy since the list is sorted and the head is faked.
	* common case the whole list is scanned.
	*/
	max = 0;
	for (fd_i = fd_head->next; fd_i; fd_i = fd_i->next) {
		if (fd_i->offset == max) {
			max++;
		}
	}
	/* max will now be datalen+1 if all fragments have been seen */

	if (max <= fd_head->datalen) {
		/* we have not received all packets yet */
		return FALSE;
	}


	if (max > (fd_head->datalen + 1)) {
		/* oops, too long fragment detected */
		fd->flags |= FD_TOOLONGFRAGMENT;
		fd_head->flags |= FD_TOOLONGFRAGMENT;
	}


	/* we have received an entire packet, defragment it and
	* free all fragments
	*/
	fragment_defragment_and_free(fd_head);

	return TRUE;
}

static void
fragment_unhash(reassembly_table *table, gpointer key)
{
	/*
	* Remove the entry from the fragment table.
	*/
	//g_hash_table_remove(table->fragment_table, key);
}


static fragment_head *
fragment_add_seq_common(reassembly_table *table, tvbuff_t *tvb,
	const int offset,
	const guint32 id, const void *data,
	guint32 frag_number, const guint32 frag_data_len,
	const gboolean more_frags, const guint32 flags,
	gpointer *orig_keyp)
{
	fragment_head *fd_head;
	gpointer orig_key;

	fd_head = lookup_fd_head(table, id, data, &orig_key);

	/* have we already seen this frame ?*/
	/* if (pinfo->fd->flags.visited) {
	if (fd_head != NULL && fd_head->flags & FD_DEFRAGMENTED) {
	if (orig_keyp != NULL)
	*orig_keyp = orig_key;
	return fd_head;
	}
	else {
	return NULL;
	}
	} */

	if (fd_head == NULL) {
		/* not found, this must be the first snooped fragment for this
		* packet. Create list-head.
		*/
		fd_head = new_head(FD_BLOCKSEQUENCE);

		if ((flags & (REASSEMBLE_FLAGS_NO_FRAG_NUMBER | REASSEMBLE_FLAGS_802_11_HACK))
			&& !more_frags) {
			/*
			* This is the last fragment for this packet, and
			* is the only one we've seen.
			*
			* Either we don't have sequence numbers, in which
			* case we assume this is the first fragment for
			* this packet, or we're doing special 802.11
			* processing, in which case we assume it's one
			* of those reassembled packets with a non-zero
			* fragment number (see packet-80211.c); just
			* return a pointer to the head of the list;
			* fragment_add_seq_check will then add it to the table
			* of reassembled packets.
			*/
			/*if (orig_keyp != NULL)
			*orig_keyp = NULL;
			fd_head->reassembled_in = pinfo->fd->num;
			return fd_head;*/
		}

		orig_key = insert_fd_head(table, fd_head, id, data);
		if (orig_keyp != NULL)
			*orig_keyp = orig_key;

		/*
		* If we weren't given an initial fragment number,
		* make it 0.
		*/
		if (flags & REASSEMBLE_FLAGS_NO_FRAG_NUMBER)
			frag_number = 0;
	}
	else {
		if (orig_keyp != NULL)
			*orig_keyp = orig_key;

		if (flags & REASSEMBLE_FLAGS_NO_FRAG_NUMBER) {
			fragment_item *fd;
			/*
			* If we weren't given an initial fragment number,
			* use the next expected fragment number as the fragment
			* number for this fragment.
			*/
			for (fd = fd_head; fd != NULL; fd = fd->next) {
				if (fd->next == NULL)
					frag_number = fd->offset + 1;
			}
		}
	}

	/*
	* XXX I've copied this over from the old separate
	* fragment_add_seq_check_work, but I'm not convinced it's doing the
	* right thing -- rav
	*
	* If we don't have all the data that is in this fragment,
	* then we can't, and don't, do reassembly on it.
	*
	* If it's the first frame, handle it as an unfragmented packet.
	* Otherwise, just handle it as a fragment.
	*
	* If "more_frags" isn't set, we get rid of the entry in the
	* hash table for this reassembly, as we don't need it any more.
	*/
	if ((flags & REASSEMBLE_FLAGS_CHECK_DATA_PRESENT) &&
		!tvb_bytes_exist(tvb, offset, frag_data_len)) {
		if (!more_frags) {
			/*
			* Remove this from the table of in-progress
			* reassemblies, and free up any memory used for
			* it in that table.
			*/
			fragment_unhash(table, *orig_keyp);
		}
		fd_head->flags |= FD_DATA_NOT_PRESENT;
		return frag_number == 0 ? fd_head : NULL;
	}

	if (fragment_add_seq_work(fd_head, tvb, offset,
		frag_number, frag_data_len, more_frags)) {
		/*
		* Reassembly is complete.
		*/
		return fd_head;
	}
	else {
		/*
		* Reassembly isn't complete.
		*/
		return NULL;
	}
}





static void
fragment_reassembled(reassembly_table *table, fragment_head *fd_head,
	const guint32 id)
{
	reassembled_key *new_key = NULL;
	fragment_item *fd;

	if (fd_head->next == NULL) {
		/*
		* This was not fragmented, so there's no fragment
		* table; just hash it using the current frame number.
		*/
		//new_key = g_slice_new(reassembled_key);
		//new_key->frame = pinfo->fd->num;
		new_key->id = id;
		g_hash_table_insert(table->reassembled_table, new_key, fd_head);
	}
	else {
		/*
		* Hash it with the frame numbers for all the frames.
		*/
		for (fd = fd_head->next; fd != NULL; fd = fd->next) {
			//new_key = g_slice_new(reassembled_key);
			new_key->frame = fd->frame;
			new_key->id = id;
			g_hash_table_insert(table->reassembled_table, new_key,
				fd_head);
		}
	}
	fd_head->flags |= FD_DEFRAGMENTED;
	//fd_head->reassembled_in = pinfo->fd->num;
}


static fragment_head *
fragment_add_seq_check_work(reassembly_table *table, tvbuff_t *tvb,
	const int offset,
	const guint32 id, const void *data,
	const guint32 frag_number,
	const guint32 frag_data_len,
	const gboolean more_frags, const guint32 flags)
{
	reassembled_key reass_key;
	fragment_head *fd_head;
	gpointer orig_key;

	/*
	* Have we already seen this frame?
	* If so, look for it in the table of reassembled packets.
	*/
	/*if (pinfo->fd->flags.visited) {
	reass_key.frame = pinfo->fd->num;
	reass_key.id = id;
	return (fragment_head *)g_hash_table_lookup(table->reassembled_table, &reass_key);
	}*/

	fd_head = fragment_add_seq_common(table, tvb, offset, id, data,
		frag_number, frag_data_len,
		more_frags,
		flags | REASSEMBLE_FLAGS_CHECK_DATA_PRESENT,
		&orig_key);
	if (fd_head) {
		if (fd_head->flags & FD_DATA_NOT_PRESENT) {
			/* this is the first fragment of a datagram with
			* truncated fragments. Don't move it to the
			* reassembled table. */
			return fd_head;
		}

		/*
		* Reassembly is complete.
		*
		* If this is in the table of in-progress reassemblies,
		* remove it from that table.  (It could be that this
		* was the first and last fragment, so that no
		* reassembly was done.)
		*/
		if (orig_key != NULL)
			fragment_unhash(table, orig_key);

		/*
		* Add this item to the table of reassembled packets.
		*/
		fragment_reassembled(table, fd_head, id);
		return fd_head;
	}
	else {
		/*
		* Reassembly isn't complete.
		*/
		return NULL;
	}
}

fragment_head *
fragment_add_seq_next(reassembly_table *table, tvbuff_t *tvb, const int offset,
	const guint32 id,
	const void *data, const guint32 frag_data_len,
	const gboolean more_frags)
{
	return fragment_add_seq_check_work(table, tvb, offset, id, data,
		0, frag_data_len, more_frags,
		REASSEMBLE_FLAGS_NO_FRAG_NUMBER);
}

void
fragment_set_tot_len(reassembly_table *table,
	const guint32 id, const void *data, const guint32 tot_len)
{
	fragment_head *fd_head;
	fragment_item *fd;
	guint32        max_offset = 0;

	fd_head = lookup_fd_head(table, id, data, NULL);
	if (!fd_head)
		return;

	/* If we're setting a block sequence number, verify that it
	* doesn't conflict with values set by existing fragments.
	* XXX - eliminate this check?
	*/
	fd = fd_head;
	if (fd_head->flags & FD_BLOCKSEQUENCE) {
		while (fd) {
			if (fd->offset > max_offset) {
				max_offset = fd->offset;
				if (max_offset > tot_len) {
					fd_head->error = "Bad total reassembly block count";
					THROW_MESSAGE(ReassemblyError, fd_head->error);
				}
			}
			fd = fd->next;
		}
	}

	if (fd_head->flags & FD_DEFRAGMENTED) {
		if (max_offset != tot_len) {
			fd_head->error = "Defragmented complete but total length not satisfied";
			THROW_MESSAGE(ReassemblyError, fd_head->error);
		}
	}

	/* We got this far so the value is sane. */
	fd_head->datalen = tot_len;
	fd_head->flags |= FD_DATALEN_SET;
}

tvbuff_t *
tvb_new_proxy(tvbuff_t *backing)
{
	tvbuff_t *tvb;

	if (backing)
		tvb = tvb_new_with_subset(backing, backing->reported_length, 0, backing->length);
	else
		tvb = tvb_new_real_data(NULL, 0, 0);

	tvb->ds_tvb = tvb;

	return tvb;
}


tvbuff_t *
tvb_new_chain(tvbuff_t *parent, tvbuff_t *backing)
{
	tvbuff_t *tvb = tvb_new_proxy(backing);

	tvb_add_to_chain(parent, tvb);
	return tvb;
}






tvbuff_t *
process_reassembled_data(tvbuff_t *tvb, const int offset,
	const char *name, fragment_head *fd_head, const fragment_items *fit,
	gboolean *update_col_infop)
{
	tvbuff_t *next_tvb;
	gboolean update_col_info;
	proto_item *frag_tree_item;

	if (fd_head != NULL) {
		/*
		* OK, we've reassembled this.
		* Is this something that's been reassembled from more
		* than one fragment?
		*/
		if (fd_head->next != NULL) {
			/*
			* Yes.
			* Allocate a new tvbuff, referring to the
			* reassembled payload, and set
			* the tvbuff to the list of tvbuffs to which
			* the tvbuff we were handed refers, so it'll get
			* cleaned up when that tvbuff is cleaned up.
			*/
			next_tvb = tvb_new_chain(tvb, fd_head->tvb_data);

			/* Add the defragmented data to the data source list. */
			//add_new_data_source(next_tvb, name);

			/* show all fragments */
			/*if (fd_head->flags & FD_BLOCKSEQUENCE) {
			update_col_info = !show_fragment_seq_tree(
			fd_head, fit, tree, pinfo, next_tvb, &frag_tree_item);
			}
			else {
			update_col_info = !show_fragment_tree(fd_head,
			fit, tree, pinfo, next_tvb, &frag_tree_item);
			}
			} */
			//else {
			/*
			* No.
			* Return a tvbuff with the payload.
			*/
		}
		else
		{
			next_tvb = tvb_new_subset_remaining(tvb, offset);
			//pinfo->fragmented = FALSE;	/* one-fragment packet */
			update_col_info = TRUE;
		}
		//}
		if (update_col_infop != NULL)
			*update_col_infop = update_col_info;
	}
	else {
		/*
		* We don't have the complete reassembled payload, or this
		* isn't the final frame of that payload.
		*/
		next_tvb = NULL;

		/*
		* If we know what frame this was reassembled in,
		* and if there's a field to use for the number of
		* the frame in which the packet was reassembled,
		* add it to the protocol tree.
		*/
		/*if (fd_head != NULL && fit->hf_reassembled_in != NULL) {
		proto_tree_add_uint(tree,
		*(fit->hf_reassembled_in), tvb,
		0, 0, fd_head->reassembled_in);
		} */

	}
	return next_tvb;
}











static void
dissect_sccp_unknown_message(tvbuff_t *message_tvb)
{
	guint32 message_length;

	message_length = tvb_length(message_tvb);

	/*proto_tree_add_text(sccp_tree, message_tvb, 0, message_length,
	"Unknown message (%u byte%s)",
	message_length, plurality(message_length, "", "s")); */
}



static int
dissect_sccp_message(tvbuff_t *tvb, proto_tree *sccp_tree)
{
	SS7_target *target = NULL;

	guint16   variable_pointer1 = 0, variable_pointer2 = 0, variable_pointer3 = 0;
	guint16   optional_pointer = 0, orig_opt_ptr = 0, var = 0, hf_var, ptr_size = 0;
	guint16   offset = 0;
	gboolean  save_fragmented;
	tvbuff_t *new_tvb = (tvbuff_t *)malloc(sizeof(tvbuff_t *));
	fragment_head *frag_msg = (fragment_head *)malloc(sizeof(fragment_head *));
	guint32   source_local_ref = 0;
	guint8    more;
	guint     msg_offset = tvb_offset_from_real_beginning(tvb);
	printf("Message offset %u \n", msg_offset);

	// Macro for getting pointer to mandatory variable parameters 
#define VARIABLE_POINTER(var, hf_var, ptr_size) \
  do {                                          \
    if (ptr_size == POINTER_LENGTH)             \
      var = tvb_get_guint8(tvb, 0);        \
    else                                        \
      var = tvb_get_letohs(tvb, 0);        \
    /*proto_tree_add_uint(sccp_tree, hf_var, tvb, \
				                        offset, ptr_size, var); */\
    var += offset;                              \
    if (ptr_size == POINTER_LENGTH_LONG)        \
      var += 1;                                 \
    offset += ptr_size;                         \
  } while (0)
	// Macro for getting pointer to optional parameters 
#define OPTIONAL_POINTER(ptr_size)                                    \
  do {                                                                  \
    if (ptr_size == POINTER_LENGTH)                                     \
      orig_opt_ptr = optional_pointer = tvb_get_guint8(tvb, offset);    \
    else                                                                \
      orig_opt_ptr = optional_pointer = tvb_get_letohs(tvb, offset);    \
   /* proto_tree_add_uint(sccp_tree, hf_sccp_optional_pointer, tvb,       \
				                        offset, ptr_size, optional_pointer);  */          \
    optional_pointer += offset;                                         \
    if (ptr_size == POINTER_LENGTH_LONG)                                \
      optional_pointer += 1;                                            \
    offset += ptr_size;                                                 \
  } while (0)                                                            \
	// Extract the message type;  all other processing is based on this 
	message_type = tvb_get_guint8(tvb, SCCP_MSG_TYPE_OFFSET); \
		printf("message type %u \n", message_type);
	offset = SCCP_MSG_TYPE_LENGTH;
	printf("offset %u \n", offset);


	//  Do not change col_add_fstr() to col_append_fstr() here: we _want_
	//  this call to overwrite whatever's currently in the INFO column (e.g.,
	//  "DATA" from the SCTP dissector).

	//  If there's something there that should not be overwritten, whoever
	// put that info there should call col_set_fence() to protect it.

	//col_add_fstr(COL_INFO, "%s ",
	//	val_to_str(message_type, sccp_message_type_acro_values, "Unknown: %d"));


	//	if (sccp_tree) {
	// add the message type to the protocol tree 
	//proto_tree_add_uint(sccp_tree, hf_sccp_message_type, tvb,
	//SCCP_MSG_TYPE_OFFSET, SCCP_MSG_TYPE_LENGTH, message_type);
	//};


	// Starting a new message dissection; clear the global assoc, SLR, and DLR values 
	dlr = INVALID_LR;
	slr = INVALID_LR;
	assoc = NULL;

	no_assoc.calling_dpc = 0;
	no_assoc.called_dpc = 0;
	no_assoc.calling_ssn = INVALID_SSN;
	no_assoc.called_ssn = INVALID_SSN;
	no_assoc.has_fw_key = FALSE;
	no_assoc.has_bw_key = FALSE;
	no_assoc.payload = SCCP_PLOAD_NONE;
	no_assoc.called_party = NULL;
	no_assoc.calling_party = NULL;
	no_assoc.extra_info = NULL;


	switch (message_type) {
	case SCCP_MSG_TYPE_CR:
		//  TTC and NTT (Japan) say that the connection-oriented messages are
		// deleted (not standardized), but they appear to be used anyway, so
		// we'll dissect it...

		printf("message type %u \n", SCCP_MSG_TYPE_CR);
		offset += dissect_sccp_parameter(tvb,
			PARAMETER_SOURCE_LOCAL_REFERENCE,
			offset, SOURCE_LOCAL_REFERENCE_LENGTH, target);
		offset += dissect_sccp_parameter(tvb,
			PARAMETER_CLASS, offset,
			PROTOCOL_CLASS_LENGTH, target);
		//assoc = get_sccp_assoc( msg_offset, slr, dlr, message_type);

		VARIABLE_POINTER(variable_pointer1, hf_sccp_variable_pointer1, POINTER_LENGTH);
		OPTIONAL_POINTER(POINTER_LENGTH);

		dissect_sccp_variable_parameter(tvb,
			PARAMETER_CALLED_PARTY_ADDRESS,
			variable_pointer1, target);
		break;

	case SCCP_MSG_TYPE_CC:

		printf("message type %u \n", "SCCP_MSG_TYPE_CC");
		//  TODO: connection has been established;  theoretically we could keep
		//  keep track of the SLR/DLR with the called/calling from the CR and
		//  track the connection (e.g., on subsequent messages regarding this
		//  SLR we could set the global vars "call*_ssn" so data could get
		//sub-dissected).

		offset += dissect_sccp_parameter(tvb,
			PARAMETER_DESTINATION_LOCAL_REFERENCE,
			offset,
			DESTINATION_LOCAL_REFERENCE_LENGTH, target);
		offset += dissect_sccp_parameter(tvb,
			PARAMETER_SOURCE_LOCAL_REFERENCE,
			offset, SOURCE_LOCAL_REFERENCE_LENGTH, target);

		//assoc = get_sccp_assoc(pinfo, msg_offset, slr, dlr, message_type);

		offset += dissect_sccp_parameter(tvb,
			PARAMETER_CLASS, offset,
			PROTOCOL_CLASS_LENGTH, target);
		OPTIONAL_POINTER(POINTER_LENGTH);
		break;


	case SCCP_MSG_TYPE_CREF:

		printf("message type %u \n", "SCCP_MSG_TYPE_CREF");
		offset += dissect_sccp_parameter(tvb,
			PARAMETER_DESTINATION_LOCAL_REFERENCE,
			offset,
			DESTINATION_LOCAL_REFERENCE_LENGTH, target);

		//assoc = get_sccp_assoc(pinfo, msg_offset, slr, dlr, message_type);

		offset += dissect_sccp_parameter(tvb,
			PARAMETER_REFUSAL_CAUSE, offset,
			REFUSAL_CAUSE_LENGTH, target);
		OPTIONAL_POINTER(POINTER_LENGTH);
		break;



	case SCCP_MSG_TYPE_RLSD:

		printf("message type %u \n", "SCCP_MSG_TYPE_RLSD");
		offset += dissect_sccp_parameter(tvb,
			PARAMETER_DESTINATION_LOCAL_REFERENCE,
			offset,
			DESTINATION_LOCAL_REFERENCE_LENGTH, target);
		offset += dissect_sccp_parameter(tvb,
			PARAMETER_SOURCE_LOCAL_REFERENCE,
			offset, SOURCE_LOCAL_REFERENCE_LENGTH, target);

		//assoc = get_sccp_assoc(pinfo, msg_offset, slr, dlr, message_type);

		offset += dissect_sccp_parameter(tvb,
			PARAMETER_RELEASE_CAUSE, offset,
			RELEASE_CAUSE_LENGTH, target);

		OPTIONAL_POINTER(POINTER_LENGTH);
		//assoc = get_sccp_assoc(pinfo, msg_offset, slr, dlr, message_type);
		break;


	case SCCP_MSG_TYPE_RLC:

		printf("message type %u \n", "SCCP_MSG_TYPE_RLC");
		offset += dissect_sccp_parameter(tvb,
			PARAMETER_DESTINATION_LOCAL_REFERENCE,
			offset,
			DESTINATION_LOCAL_REFERENCE_LENGTH, target);
		offset += dissect_sccp_parameter(tvb,
			PARAMETER_SOURCE_LOCAL_REFERENCE,
			offset, SOURCE_LOCAL_REFERENCE_LENGTH, target);

		//assoc = get_sccp_assoc(pinfo, msg_offset, slr, dlr, message_type);
		break;

	case SCCP_MSG_TYPE_DT1:

		printf("message type %u \n", "SCCP_MSG_TYPE_DT1");

		source_local_ref = tvb_get_letoh24(tvb, offset);
		offset += dissect_sccp_parameter(tvb,
			PARAMETER_DESTINATION_LOCAL_REFERENCE,
			offset,
			DESTINATION_LOCAL_REFERENCE_LENGTH, target);

		//assoc = get_sccp_assoc(pinfo, msg_offset, slr, dlr, message_type);

		more = tvb_get_guint8(tvb, offset) & SEGMENTING_REASSEMBLING_MASK;

		offset += dissect_sccp_parameter(tvb,
			PARAMETER_SEGMENTING_REASSEMBLING,
			offset, SEGMENTING_REASSEMBLING_LENGTH, target);
		VARIABLE_POINTER(variable_pointer1, hf_sccp_variable_pointer1, POINTER_LENGTH);

		// Reassemble 
		if (!sccp_xudt_desegment) {
			proto_tree_add_text(sccp_tree, tvb, variable_pointer1,
				tvb_get_guint8(tvb, variable_pointer1) + 1,
				"Segmented Data");
			dissect_sccp_variable_parameter(tvb,
				PARAMETER_DATA, variable_pointer1, target);

		}
		else {
			//save_fragmented = pinfo->fragmented;
			//pinfo->fragmented = TRUE;
			frag_msg = fragment_add_seq_next(&sccp_xudt_msg_reassembly_table,
				tvb, variable_pointer1 + 1,

				source_local_ref,                       // ID for fragments belonging together 
				NULL,
				tvb_get_guint8(tvb, variable_pointer1), // fragment length - to the end 
				more);                                  // More fragments? 

														//	new_tvb = process_reassembled_data(tvb, variable_pointer1 + 1, pinfo,
														//"Reassembled SCCP", frag_msg,
														//&sccp_xudt_msg_frag_items, NULL,
														//tree);

														//if (frag_msg && frag_msg->next) { 
														//	col_append_str(pinfo->cinfo, COL_INFO, "(Message reassembled) ");
														//}
														//else if (more) { 
														//	col_append_str(pinfo->cinfo, COL_INFO, "(Message fragment) ");
														//}

														//	pinfo->fragmented = save_fragmented;

														//	if (new_tvb)
														//		dissect_sccp_data_param(new_tvb, pinfo, tree);
														//}

														//End reassemble 
			break;


	case SCCP_MSG_TYPE_DT2:


		printf("message type %u \n", "SCCP_MSG_TYPE_DT2");
		offset += dissect_sccp_parameter(tvb,
			PARAMETER_DESTINATION_LOCAL_REFERENCE,
			offset,
			DESTINATION_LOCAL_REFERENCE_LENGTH, target);

		//assoc = get_sccp_assoc(pinfo, msg_offset, slr, dlr, message_type);

		offset += dissect_sccp_parameter(tvb,
			PARAMETER_SEQUENCING_SEGMENTING, offset,
			SEQUENCING_SEGMENTING_LENGTH, target);
		break;


	case SCCP_MSG_TYPE_AK:

		printf("message type %u \n", "SCCP_MSG_TYPE_AK");
		offset += dissect_sccp_parameter(tvb,
			PARAMETER_DESTINATION_LOCAL_REFERENCE,
			offset,
			DESTINATION_LOCAL_REFERENCE_LENGTH, target);

		//assoc = get_sccp_assoc(pinfo, msg_offset, slr, dlr, message_type);

		offset += dissect_sccp_parameter(tvb,
			PARAMETER_RECEIVE_SEQUENCE_NUMBER,
			offset, RECEIVE_SEQUENCE_NUMBER_LENGTH, target);
		offset += dissect_sccp_parameter(tvb,
			PARAMETER_CREDIT, offset, CREDIT_LENGTH, target);
		break;

	case SCCP_MSG_TYPE_UDT:

		printf("message type %s \n", "SCCP_MSG_TYPE_UDT");
		//pinfo->sccp_info = sccp_msg = new_ud_msg(pinfo, message_type);

		offset += dissect_sccp_parameter(tvb,
			PARAMETER_CLASS, offset,
			PROTOCOL_CLASS_LENGTH,target);
		VARIABLE_POINTER(variable_pointer1, hf_sccp_variable_pointer1, POINTER_LENGTH);
		VARIABLE_POINTER(variable_pointer2, hf_sccp_variable_pointer2, POINTER_LENGTH);
		VARIABLE_POINTER(variable_pointer3, hf_sccp_variable_pointer3, POINTER_LENGTH);

		//assoc = get_sccp_assoc(pinfo, msg_offset, slr, dlr, message_type);

		dissect_sccp_variable_parameter(tvb,
			PARAMETER_CALLED_PARTY_ADDRESS,
			variable_pointer1, target);
		dissect_sccp_variable_parameter(tvb,
			PARAMETER_CALLING_PARTY_ADDRESS,
			variable_pointer2, target);

		dissect_sccp_variable_parameter(tvb, PARAMETER_DATA,
			variable_pointer3, target);
		//dissect_sccp_variable_parameter(tvb, sccp_tree, tPARAMETER_DATA,
		//variable_pointer3);
		break;




	case SCCP_MSG_TYPE_UDTS:
	{
		printf("message type %u \n", "SCCP_MSG_TYPE_UDTS");
		//gboolean save_in_error_pkt = pinfo->flags.in_error_pkt;
		//	pinfo->flags.in_error_pkt = TRUE;

		//pinfo->sccp_info = sccp_msg = new_ud_msg(pinfo, message_type);

		offset += dissect_sccp_parameter(tvb,
			PARAMETER_RETURN_CAUSE, offset,
			RETURN_CAUSE_LENGTH, target);

		VARIABLE_POINTER(variable_pointer1, hf_sccp_variable_pointer1, POINTER_LENGTH);
		VARIABLE_POINTER(variable_pointer2, hf_sccp_variable_pointer2, POINTER_LENGTH);
		VARIABLE_POINTER(variable_pointer3, hf_sccp_variable_pointer3, POINTER_LENGTH);

		//assoc = get_sccp_assoc(pinfo, msg_offset, slr, dlr, message_type);

		dissect_sccp_variable_parameter(tvb,
			PARAMETER_CALLED_PARTY_ADDRESS,
			variable_pointer1, target);

		dissect_sccp_variable_parameter(tvb,
			PARAMETER_CALLING_PARTY_ADDRESS,
			variable_pointer2, target);

		dissect_sccp_variable_parameter(tvb, PARAMETER_DATA,
			variable_pointer3, target);
		//pinfo->flags.in_error_pkt = save_in_error_pkt;
		break;
	}



	case SCCP_MSG_TYPE_ED:

		printf("message type %u \n", "SCCP_MSG_TYPE_ED");
		offset += dissect_sccp_parameter(tvb,
			PARAMETER_DESTINATION_LOCAL_REFERENCE,
			offset,
			DESTINATION_LOCAL_REFERENCE_LENGTH, target);

		//assoc = get_sccp_assoc(pinfo, msg_offset, slr, dlr, message_type);

		VARIABLE_POINTER(variable_pointer1, hf_sccp_variable_pointer1, POINTER_LENGTH);

		dissect_sccp_variable_parameter(tvb, PARAMETER_DATA,
			variable_pointer1, target);
		break;



	case SCCP_MSG_TYPE_EA:

		printf("message type %u \n", "SCCP_MSG_TYPE_EA");
		offset += dissect_sccp_parameter(tvb,
			PARAMETER_DESTINATION_LOCAL_REFERENCE,
			offset,
			DESTINATION_LOCAL_REFERENCE_LENGTH, target);
		//assoc = get_sccp_assoc(pinfo, msg_offset, slr, dlr, message_type);
		break;



	case SCCP_MSG_TYPE_RSR:

		printf("message type %u \n", "SCCP_MSG_TYPE_RSR");
		offset += dissect_sccp_parameter(tvb,
			PARAMETER_DESTINATION_LOCAL_REFERENCE,
			offset,
			DESTINATION_LOCAL_REFERENCE_LENGTH, target);
		offset += dissect_sccp_parameter(tvb,
			PARAMETER_SOURCE_LOCAL_REFERENCE,
			offset, SOURCE_LOCAL_REFERENCE_LENGTH, target);
		offset += dissect_sccp_parameter(tvb,
			PARAMETER_RESET_CAUSE, offset,
			RESET_CAUSE_LENGTH, target);
		//assoc = get_sccp_assoc(pinfo, msg_offset, slr, dlr, message_type);
		break;


	case SCCP_MSG_TYPE_RSC:

		printf("message type %u \n", "SCCP_MSG_TYPE_RSC");
		offset += dissect_sccp_parameter(tvb,
			PARAMETER_DESTINATION_LOCAL_REFERENCE,
			offset,
			DESTINATION_LOCAL_REFERENCE_LENGTH, target);
		offset += dissect_sccp_parameter(tvb,
			PARAMETER_SOURCE_LOCAL_REFERENCE,
			offset, SOURCE_LOCAL_REFERENCE_LENGTH, target);
		// assoc = get_sccp_assoc(pinfo, msg_offset, slr, dlr, message_type);
		break;




	case SCCP_MSG_TYPE_ERR:

		printf("message type %u \n", "SCCP_MSG_TYPE_ERR");
		offset += dissect_sccp_parameter(tvb,
			PARAMETER_DESTINATION_LOCAL_REFERENCE,
			offset,
			DESTINATION_LOCAL_REFERENCE_LENGTH, target);
		offset += dissect_sccp_parameter(tvb,
			PARAMETER_ERROR_CAUSE, offset,
			ERROR_CAUSE_LENGTH, target);
		//assoc = get_sccp_assoc(pinfo, msg_offset, slr, dlr, message_type);
		break;



	case SCCP_MSG_TYPE_IT:

		printf("message type %u \n", "SCCP_MSG_TYPE_IT");
		offset += dissect_sccp_parameter(tvb,
			PARAMETER_DESTINATION_LOCAL_REFERENCE,
			offset,
			DESTINATION_LOCAL_REFERENCE_LENGTH, target);
		offset += dissect_sccp_parameter(tvb,
			PARAMETER_SOURCE_LOCAL_REFERENCE,
			offset, SOURCE_LOCAL_REFERENCE_LENGTH, target);
		//assoc = get_sccp_assoc(pinfo, msg_offset, slr, dlr, message_type);
		offset += dissect_sccp_parameter(tvb,
			PARAMETER_CLASS, offset,
			PROTOCOL_CLASS_LENGTH, target);
		offset += dissect_sccp_parameter(tvb,
			PARAMETER_SEQUENCING_SEGMENTING,
			offset, SEQUENCING_SEGMENTING_LENGTH, target);
		offset += dissect_sccp_parameter(tvb,
			PARAMETER_CREDIT, offset, CREDIT_LENGTH, target);
		break;



	case SCCP_MSG_TYPE_XUDT:

		printf("message type %u \n", "SCCP_MSG_TYPE_XUDT");
		//pinfo->sccp_info = sccp_msg = new_ud_msg(pinfo, message_type);
		offset += dissect_sccp_parameter(tvb,
			PARAMETER_CLASS, offset,
			PROTOCOL_CLASS_LENGTH, target);
		offset += dissect_sccp_parameter(tvb,
			PARAMETER_HOP_COUNTER, offset,
			HOP_COUNTER_LENGTH, target);

		VARIABLE_POINTER(variable_pointer1, hf_sccp_variable_pointer1, POINTER_LENGTH);
		VARIABLE_POINTER(variable_pointer2, hf_sccp_variable_pointer2, POINTER_LENGTH);
		VARIABLE_POINTER(variable_pointer3, hf_sccp_variable_pointer3, POINTER_LENGTH);
		OPTIONAL_POINTER(POINTER_LENGTH);

		//  Optional parameters are Segmentation and Importance
		// NOTE 2 - Segmentation Should not be present in case of a single XUDT
		// message.


		//assoc = get_sccp_assoc(pinfo, msg_offset, slr, dlr, message_type);

		dissect_sccp_variable_parameter(tvb,
			PARAMETER_CALLED_PARTY_ADDRESS,
			variable_pointer1, target);
		dissect_sccp_variable_parameter(tvb,
			PARAMETER_CALLING_PARTY_ADDRESS,
			variable_pointer2, target);
		// long comment to be revised
		if (tvb_get_guint8(tvb, optional_pointer) == PARAMETER_SEGMENTATION) {
			if (!sccp_xudt_desegment) {
				proto_tree_add_text(sccp_tree, tvb, variable_pointer3, tvb_get_guint8(tvb, variable_pointer3) + 1, "Segmented Data");
			}
			else {
				guint8 octet;
				gboolean more_frag = TRUE;

				/// Get the first octet of parameter Segmentation, Ch 3.17 in Q.713
				// Bit 8 of octet 1 is used for First segment indication
				// Bit 7 of octet 1 is used to keep in the message in sequence
				//         delivery option required by the SCCP user
				// Bits 6 and 5 in octet 1 are spare bits.
				//Bits 4-1 of octet 1 are used to indicate the number of
				//           remaining segments.
				// The values 0000 to 1111 are possible; the value 0000 indicates
				// the last segment.

				octet = tvb_get_guint8(tvb, optional_pointer + 2);
				source_local_ref = tvb_get_letoh24(tvb, optional_pointer + 3);

				if ((octet & 0x0f) == 0)
					more_frag = FALSE;

				//save_fragmented = pinfo->fragmented;
				//pinfo->fragmented = TRUE;
				//frag_msg = fragment_add_seq_next(&sccp_xudt_msg_reassembly_table,
				//	tvb, variable_pointer3 + 1,
				//	pinfo,
				//	source_local_ref,                            // ID for fragments belonging together 
				//	NULL,
				//tvb_get_guint8(tvb, variable_pointer3),       // fragment length - to the end 
				//more_frag);                          // More fragments? 

				if ((octet & 0x80) == 0x80) //First segment, set number of segments
					fragment_set_tot_len(&sccp_xudt_msg_reassembly_table,
						source_local_ref, NULL, (octet & 0xf));

				new_tvb = process_reassembled_data(tvb, variable_pointer3 + 1,
					"Reassembled SCCP",
					frag_msg,
					&sccp_xudt_msg_frag_items,
					NULL);
				/*if (frag_msg) { // Reassembled
				col_append_str(COL_INFO, "(Message reassembled) ");
				}
				else { // Not last packet of reassembled message
				col_append_str( COL_INFO, "(Message fragment) ");
				} */
				//	pinfo->fragmented = save_fragmented;

				if (new_tvb)
					dissect_sccp_data_param(new_tvb);
			}
		}
		else {
			dissect_sccp_variable_parameter(tvb,
				PARAMETER_DATA, variable_pointer3, target);
		}
		break;




	case SCCP_MSG_TYPE_XUDTS:
	{

		printf("message type %u \n", "SCCP_MSG_TYPE_XUDTS");
		//gboolean save_in_error_pkt = pinfo->flags.in_error_pkt;
		//pinfo->flags.in_error_pkt = TRUE;

		//pinfo->sccp_info = sccp_msg = new_ud_msg(pinfo, message_type);
		offset += dissect_sccp_parameter(tvb,
			PARAMETER_RETURN_CAUSE, offset,
			RETURN_CAUSE_LENGTH, target);
		offset += dissect_sccp_parameter(tvb,
			PARAMETER_HOP_COUNTER, offset,
			HOP_COUNTER_LENGTH, target);

		VARIABLE_POINTER(variable_pointer1, hf_sccp_variable_pointer1, POINTER_LENGTH);
		VARIABLE_POINTER(variable_pointer2, hf_sccp_variable_pointer2, POINTER_LENGTH);
		VARIABLE_POINTER(variable_pointer3, hf_sccp_variable_pointer3, POINTER_LENGTH);
		OPTIONAL_POINTER(POINTER_LENGTH);

		//assoc = get_sccp_assoc(pinfo, msg_offset, slr, dlr, message_type);

		dissect_sccp_variable_parameter(tvb,
			PARAMETER_CALLED_PARTY_ADDRESS,
			variable_pointer1, target);
		dissect_sccp_variable_parameter(tvb,
			PARAMETER_CALLING_PARTY_ADDRESS,
			variable_pointer2, target);

		if (tvb_get_guint8(tvb, optional_pointer) == PARAMETER_SEGMENTATION) {
			if (!sccp_xudt_desegment) {
				proto_tree_add_text(sccp_tree, tvb, variable_pointer3, tvb_get_guint8(tvb, variable_pointer3) + 1, "Segmented Data");

			}
			else {
				guint8 octet;
				gboolean more_frag = TRUE;


				// Get the first octet of parameter Segmentation, Ch 3.17 in Q.713
				//Bit 8 of octet 1 is used for First segment indication
				//Bit 7 of octet 1 is used to keep in the message in sequence
				//         delivery option required by the SCCP user
				// Bits 6 and 5 in octet 1 are spare bits.
				// Bits 4-1 of octet 1 are used to indicate the number of
				//            remaining segments.
				// The values 0000 to 1111 are possible; the value 0000 indicates
				// the last segment.

				octet = tvb_get_guint8(tvb, optional_pointer + 2);
				source_local_ref = tvb_get_letoh24(tvb, optional_pointer + 3);

				if ((octet & 0x0f) == 0)
					more_frag = FALSE;

				//save_fragmented = pinfo->fragmented;
				//pinfo->fragmented = TRUE;
				frag_msg = fragment_add_seq_next(&sccp_xudt_msg_reassembly_table,
					tvb, variable_pointer3 + 1,

					source_local_ref,                            // ID for fragments belonging together 
					NULL,
					tvb_get_guint8(tvb, variable_pointer3),      // fragment length - to the end 
					more_frag);                                  // More fragments? 

				if ((octet & 0x80) == 0x80) //First segment, set number of segments
					fragment_set_tot_len(&sccp_xudt_msg_reassembly_table,
						source_local_ref, NULL, (octet & 0xf));

				new_tvb = process_reassembled_data(tvb, variable_pointer3 + 1,
					"Reassembled SCCP",
					frag_msg,
					&sccp_xudt_msg_frag_items,
					NULL);

				if (frag_msg) { // Reassembled 
								//col_append_str(pinfo->cinfo, COL_INFO, "(Message reassembled) ");
				}
				else { // Not last packet of reassembled message 
					   //col_append_str(pinfo->cinfo, COL_INFO, "(Message fragment) ");
				}

				//pinfo->fragmented = save_fragmented;

				if (new_tvb)
					dissect_sccp_data_param(new_tvb);
			}
		}
		else {
			dissect_sccp_variable_parameter(tvb,
				PARAMETER_DATA, variable_pointer3, target);
		}
		//pinfo->flags.in_error_pkt = save_in_error_pkt;
		break;
	}
	case SCCP_MSG_TYPE_LUDT:

		printf("message type %u \n", "SCCP_MSG_TYPE_LUDT");
		//pinfo->sccp_info = sccp_msg = new_ud_msg(pinfo, message_type);

		offset += dissect_sccp_parameter(tvb,
			PARAMETER_CLASS, offset,
			PROTOCOL_CLASS_LENGTH, target);
		offset += dissect_sccp_parameter(tvb,
			PARAMETER_HOP_COUNTER, offset,
			HOP_COUNTER_LENGTH, target);

		VARIABLE_POINTER(variable_pointer1, hf_sccp_variable_pointer1, POINTER_LENGTH_LONG);
		VARIABLE_POINTER(variable_pointer2, hf_sccp_variable_pointer2, POINTER_LENGTH_LONG);
		VARIABLE_POINTER(variable_pointer3, hf_sccp_variable_pointer3, POINTER_LENGTH_LONG);
		OPTIONAL_POINTER(POINTER_LENGTH_LONG);

		//assoc = get_sccp_assoc(pinfo, msg_offset, slr, dlr, message_type);

		dissect_sccp_variable_parameter(tvb,
			PARAMETER_CALLED_PARTY_ADDRESS,
			variable_pointer1, target);
		dissect_sccp_variable_parameter(tvb,
			PARAMETER_CALLING_PARTY_ADDRESS,
			variable_pointer2, target);
		dissect_sccp_variable_parameter(tvb,
			PARAMETER_LONG_DATA, variable_pointer3, target);
		break;


	case SCCP_MSG_TYPE_LUDTS:

		printf("message type %u \n", "SCCP_MSG_TYPE_LUDTS");
		//pinfo->sccp_info = sccp_msg = new_ud_msg(pinfo, message_type);
		offset += dissect_sccp_parameter(tvb,
			PARAMETER_RETURN_CAUSE, offset,
			RETURN_CAUSE_LENGTH, target);
		offset += dissect_sccp_parameter(tvb,
			PARAMETER_HOP_COUNTER, offset,
			HOP_COUNTER_LENGTH, target);

		VARIABLE_POINTER(variable_pointer1, hf_sccp_variable_pointer1, POINTER_LENGTH_LONG);
		VARIABLE_POINTER(variable_pointer2, hf_sccp_variable_pointer2, POINTER_LENGTH_LONG);
		VARIABLE_POINTER(variable_pointer3, hf_sccp_variable_pointer3, POINTER_LENGTH_LONG);
		OPTIONAL_POINTER(POINTER_LENGTH_LONG);

		//assoc = get_sccp_assoc(pinfo, msg_offset, slr, dlr, message_type);

		dissect_sccp_variable_parameter(tvb,
			PARAMETER_CALLED_PARTY_ADDRESS,
			variable_pointer1, target);
		dissect_sccp_variable_parameter(tvb,
			PARAMETER_CALLING_PARTY_ADDRESS,
			variable_pointer2, target);
		dissect_sccp_variable_parameter(tvb,
			PARAMETER_LONG_DATA, variable_pointer3, target);
		break;



	default:
		dissect_sccp_unknown_message(tvb);
		//..................................................................case end ---------..........................//
		}

	}
	/*



	if (orig_opt_ptr)
	dissect_sccp_optional_parameters(tvb, pinfo, sccp_tree, tree,
	optional_pointer);

	if (trace_sccp && assoc && (assoc != &no_assoc)) {
	proto_item *pi = proto_tree_add_uint(sccp_tree, hf_sccp_assoc_id, tvb, 0, 0, assoc->id);
	proto_tree *pt = proto_item_add_subtree(pi, ett_sccp_assoc);
	PROTO_ITEM_SET_GENERATED(pi);
	if (assoc->msgs) {
	sccp_msg_info_t *m;
	for (m = assoc->msgs; m; m = m->data.co.next) {
	pi = proto_tree_add_uint(pt, hf_sccp_assoc_msg, tvb, 0, 0, m->framenum);

	if (assoc->payload != SCCP_PLOAD_NONE)
	proto_item_append_text(pi, " %s", val_to_str(assoc->payload, assoc_protos, "Unknown: %d"));

	if (m->data.co.label)
	proto_item_append_text(pi, " %s", m->data.co.label);

	if ((m->framenum == PINFO_FD_NUM(pinfo)) && (m->offset == msg_offset)) {
	tap_queue_packet(sccp_tap, pinfo, m);
	proto_item_append_text(pi, " (current)");
	}
	PROTO_ITEM_SET_GENERATED(pi);
	}
	}
	}
	*/

	return offset;
}



static void
dissect_sccp(tvbuff_t *tvb, SS7_target* ss7_val)
{
	proto_tree *sccp_tree = NULL;
	const mtp3_addr_pc_t *mtp3_addr_p;

	/* Make entry in the Protocol column on summary display */

	/* In the interest of speed, if "tree" is NULL, don't do any work not
	necessary to generate protocol tree items. */

	/* Set whether message is UPLINK, DOWNLINK, or of UNKNOWN direction */

	/* dissect the message */
	dissect_sccp_message(tvb, sccp_tree);

}


int main()
{
	ifstream Myfile;

	guint8 * ptr;
	long lsize;
	long length;
	SS7_target * Mystr_val;

	FILE * data = NULL;
	tvbuff_t * tvb = (tvbuff_t*)malloc(sizeof(tvbuff_t));
	Mystr_val = (SS7_target *)malloc(sizeof(SS7_target));
	fopen_s(&data, "sccp_1", "rb");


	if (data == NULL)
	{
		printf("Fail to Open file!!");
	}
	else
	{
		printf("file is opened !!!\n");
		fseek(data, 0, SEEK_END);
		lsize = ftell(data);
		rewind(data);
		ptr = (guint8*)malloc(sizeof(guint8)*lsize);
		length = fread(ptr, sizeof(guint8), lsize, data);
		tvb->real_data = ptr;
		tvb->length = length;
		tvb->reported_length = length;

		//	tvb->next = (tvbuff_t*)malloc(sizeof(guint8));
		//tvb->next->ops = (tvb_ops*)malloc(sizeof(guint8));

		//tvb->next->initialized = (tvb_ops*)malloc(sizeof(guint8));;
		//		tvb->next->flags = (guint8)malloc(sizeof(guint8));;
		//tvb->next->ds_tvb = (tvbuff_t*)malloc(sizeof(guint8));;
		//tvb->next->raw_offset = (guint8)malloc(sizeof(guint8));;


		//tvb->ops = 0;
		//tvb->ds_tvb = 0;

		dissect_sccp(tvb, Mystr_val);


		//	//exit(EXIT_FAILURE);


		//cout << lsize << endl ;
		//Myfile.close();
	}
	return 0;
}