
#include <stdio.h>
#include <fstream>
#include <cmath>
#include <cstdlib>
//#include "glib.h"
//#include <gmodule.h>

typedef unsigned char guint8;
typedef signed int gint;
typedef unsigned int guint;
typedef signed char gint8;
typedef bool gboolean;
typedef long gsize;
typedef unsigned int guint32;
typedef signed short gint16;
typedef unsigned short guint16;
typedef char   gchar;
typedef signed int gint32;
typedef unsigned long guint64;
typedef double  gdouble;
typedef unsigned char   guchar;
typedef unsigned char       BYTE;

typedef void* gpointer;


#define SCCP_MSG_TYPE_OFFSET 0
#define SCCP_MSG_TYPE_LENGTH 1
#define POINTER_LENGTH       1
#define POINTER_LENGTH_LONG  2

#define FragmentBoundsError	3
#define ReportedBoundsError	2
#define BoundsError		1

#define XCEPT_GROUP_WIRESHARK 1

#ifndef FALSE
#define FALSE               0
#endif

#ifndef TRUE
#define TRUE                1
#endif


#ifndef CONST
#define CONST const
#endif

#define THROW throw
#define THROW_ON(cond, x) /* G_STMT_START { \
					if ((cond)) \
																except_throw(XCEPT_GROUP_WIRESHARK, (x), NULL); \
																																						} G_STMT_END */

#define CATCH_ALL \
	if (except_state == 0 && exc != 0 && \
	    (except_state|=EXCEPT_CAUGHT)) \
		/* user's code goes here */

#define THROW_MESSAGE(x, y) \
	/* except_throw(XCEPT_GROUP_WIRESHARK, (x), (y)) */

typedef unsigned long       DWORD;

#define SCCP_MSG_TYPE_CR    0x01
#define SCCP_MSG_TYPE_CC    0x02
#define SCCP_MSG_TYPE_CREF  0x03
#define SCCP_MSG_TYPE_RLSD  0x04
#define SCCP_MSG_TYPE_RLC   0x05
#define SCCP_MSG_TYPE_DT1   0x06
#define SCCP_MSG_TYPE_DT2   0x07
#define SCCP_MSG_TYPE_AK    0x08
#define SCCP_MSG_TYPE_UDT   0x09
#define SCCP_MSG_TYPE_UDTS  0x0a
#define SCCP_MSG_TYPE_ED    0x0b
#define SCCP_MSG_TYPE_EA    0x0c
#define SCCP_MSG_TYPE_RSR   0x0d
#define SCCP_MSG_TYPE_RSC   0x0e
#define SCCP_MSG_TYPE_ERR   0x0f
#define SCCP_MSG_TYPE_IT    0x10
#define SCCP_MSG_TYPE_XUDT  0x11
#define SCCP_MSG_TYPE_XUDTS 0x12
#define SCCP_MSG_TYPE_LUDT  0x13
#define SCCP_MSG_TYPE_LUDTS 0x14

#define PARAMETER_END_OF_OPTIONAL_PARAMETERS    0x00
#define PARAMETER_DESTINATION_LOCAL_REFERENCE   0x01
#define PARAMETER_SOURCE_LOCAL_REFERENCE        0x02
#define PARAMETER_CALLED_PARTY_ADDRESS          0x03
#define PARAMETER_CALLING_PARTY_ADDRESS         0x04
#define PARAMETER_CLASS                         0x05
#define PARAMETER_SEGMENTING_REASSEMBLING       0x06
#define PARAMETER_RECEIVE_SEQUENCE_NUMBER       0x07
#define PARAMETER_SEQUENCING_SEGMENTING         0x08
#define PARAMETER_CREDIT                        0x09
#define PARAMETER_RELEASE_CAUSE                 0x0a
#define PARAMETER_RETURN_CAUSE                  0x0b
#define PARAMETER_RESET_CAUSE                   0x0c
#define PARAMETER_ERROR_CAUSE                   0x0d
#define PARAMETER_REFUSAL_CAUSE                 0x0e
#define PARAMETER_DATA                          0x0f
#define PARAMETER_SEGMENTATION                  0x10
#define PARAMETER_HOP_COUNTER                   0x11
/* Importance is ITU only */
#define PARAMETER_IMPORTANCE                    0x12
#define PARAMETER_LONG_DATA                     0x13
/* ISNI is ANSI only */
#define PARAMETER_ISNI                          0xfa

#define INVALID_LR 0xffffff /* a reserved value */
#define ADDRESS_SSN_LENGTH      1
#define INVALID_SSN             0xff

#define END_OF_OPTIONAL_PARAMETERS_LENGTH       1
#define DESTINATION_LOCAL_REFERENCE_LENGTH      3
#define SOURCE_LOCAL_REFERENCE_LENGTH           3
#define PROTOCOL_CLASS_LENGTH                   1
#define RECEIVE_SEQUENCE_NUMBER_LENGTH          1
#define CREDIT_LENGTH                           1
#define RELEASE_CAUSE_LENGTH                    1
#define RETURN_CAUSE_LENGTH                     1
#define RESET_CAUSE_LENGTH                      1
#define ERROR_CAUSE_LENGTH                      1
#define REFUSAL_CAUSE_LENGTH                    1
#define HOP_COUNTER_LENGTH                      1
#define IMPORTANCE_LENGTH                       1

#define PARAMETER_LENGTH_LENGTH                 1
#define PARAMETER_LONG_DATA_LENGTH_LENGTH       2
#define PARAMETER_TYPE_LENGTH                   1

#define SEGMENTING_REASSEMBLING_LENGTH 1
#define SEGMENTING_REASSEMBLING_MASK   0x01
#define NO_MORE_DATA 0
#define MORE_DATA    1

#define SEQUENCING_SEGMENTING_LENGTH            2
#define SEQUENCING_SEGMENTING_SSN_LENGTH        1
#define SEQUENCING_SEGMENTING_RSN_LENGTH        1
#define SEND_SEQUENCE_NUMBER_MASK               0xfe
#define RECEIVE_SEQUENCE_NUMBER_MASK            0xfe
#define SEQUENCING_SEGMENTING_MORE_MASK         0x01

#define ADDRESS_INDICATOR_LENGTH        1

#define ANSI_NATIONAL_MASK              0x80

#define EI_INIT {-1, -1}

#define ITU_RESERVED_MASK               0x80
#define ROUTING_INDICATOR_MASK          0x40
#define ROUTING_INDICATOR_SHIFT 6
#define GTI_MASK                        0x3C

#define ITU_SSN_INDICATOR_MASK          0x02
#define ROUTE_ON_SSN            0x1

#define ITU_PC_INDICATOR_MASK           0x01

#define ITU_PC_LENGTH     2

#define AI_GTI_NO_GT                    0x0
#define ROUTE_ON_GT             0x0
#define ANSI_PC_INDICATOR_MASK          0x02

#define ANSI_SSN_INDICATOR_MASK         0x01

#define GT_NP_LAND_MOBILE       0x06
#define ANSI_PC_LENGTH    3
#define JAPAN_PC_LENGTH   2
#define CLASS_CLASS_MASK                0xf
#define CLASS_SPARE_HANDLING_SHIFT      4
#define ANSI_ISNI_TI_MASK                0x10
#define ANSI_ISNI_ROUTING_CONTROL_LENGTH 1
#define ANSI_ISNI_TI_SHIFT               4
#define ANSI_ISNI_TYPE_1 0x1


static int hf_sccp_called_ansi_pc = -1;
static int hf_sccp_calling_ansi_pc = -1;
static int hf_sccp_called_chinese_pc = -1;
static int hf_sccp_calling_chinese_pc = -1;
static gint ett_sccp_called_pc = -1;
static gint ett_sccp_calling_pc = -1;
static int hf_sccp_called_pc_network = -1;
static int hf_sccp_calling_pc_network = -1;
static int hf_sccp_called_pc_cluster = -1;
static int hf_sccp_calling_pc_cluster = -1;
static int hf_sccp_called_pc_member = -1;
static int hf_sccp_calling_pc_member = -1;

#define is_connectionless(m) \
  ( m == SCCP_MSG_TYPE_UDT || m == SCCP_MSG_TYPE_UDTS      \
    || m == SCCP_MSG_TYPE_XUDT|| m == SCCP_MSG_TYPE_XUDTS  \
    || m == SCCP_MSG_TYPE_LUDT|| m == SCCP_MSG_TYPE_LUDTS)

//#define const EMIT WARNING C4005
#ifdef WS_DLL_PUBLIC
#undef WS_DLL_PUBLIC
#endif
/* GCC */
/*#define WS_DLL_PUBLIC_DEF __attribute__ ((dllimport))
#elif ! (defined ENABLE_STATIC) /* ! __GNUC__ */
#define WS_DLL_PUBLIC_DEF __declspec(dllexport)


#define WS_DLL_PUBLIC	WS_DLL_PUBLIC_DEF extern

/*#define THROW(x) \
except_throw(XCEPT_GROUP_WIRESHARK, (x), NULL) */

/* #define DISSECTOR_ASSERT(expression)  \
{ if(!(expression)) _asm { int 3}; }
#endif */

#define DISSECTOR_ASSERT(expression)  \
  ((void) ((expression) ? (void)0 : \
   __DISSECTOR_ASSERT (expression, __FILE__, __LINE__))) \
   __DISSECTOR_ASSERT_STATIC_ANALYSIS_HINT(expression)

#define DISSECTOR_ASSERT_NOT_REACHED()  \

/*#define proto_tree_add_uint(tree, hfinfo, tvb, start, length, value) \
proto_tree_add_uint(tree, (hfinfo)->id, tvb, start, length, value)  */

#define TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo) \
//#define TRY_TO_FAKE_THIS_REPR(pi) 
#define va_dcl va_list va_alist;
#define va_start(ap) ((void)(ap = (va_list)&va_alist))
#define __crt_va_end(ap)        ((void)(ap = (va_list)0))
#define va_end __crt_va_end

#define             g_slice_new0(type)
#define GDestroyNotify(exp)
void
(*GDestroyNotify) (gpointer data);

#define	g_slice_new()

#define FIELD_INFO_NEW(fi)  fi = g_slice_new(field_info)
#define FIELD_INFO_FREE(fi) g_slice_free(field_info, fi)

#define G_LIKELY(expr) /*(__builtin_expect (_G_BOOLEAN_EXPR(expr), 1)) */

#define g_malloc(expression)
gpointer
g_malloc(gsize n_bytes);
#define g_free
/*void
g_free(gpointer mem); */

#define             g_assert_not_reached()


#define DUMPER_ENCAP(d) GPOINTER_TO_INT(g_hash_table_lookup(dumper_encaps,d))

#define DISSECTOR_ASSERT(expression)  \

#define pletoh24(p) ((guint32)*((const guint8 *)(p)+2)<<16|  \
                     (guint32)*((const guint8 *)(p)+1)<<8|  \
                     (guint32)*((const guint8 *)(p)+0)<<0)
//////////////////////////////////////////////////////////////////////////////
#define g_hash_table_insert(expression)
gboolean
g_hash_table_insert(GHashTable *hash_table,
	gpointer key,
	gpointer value);
#define g_hash_table_lookup_extended
/*gboolean
g_hash_table_lookup_extended(GHashTable *hash_table,
gconstpointer lookup_key,
gpointer *orig_key,
gpointer *value); */

#define pntohs(p)   ((guint16)                       \
                     ((guint16)*((const guint8 *)(p)+0)<<8|  \
                      (guint16)*((const guint8 *)(p)+1)<<0))


#define GT_SIGNAL_LENGTH     1
#define GT_ODD_SIGNAL_MASK   0x0f
#define GT_EVEN_SIGNAL_MASK  0xf0
#define GT_EVEN_SIGNAL_SHIFT 4
#define GT_MAX_SIGNALS (32*7)	
#define HASH_IS_REAL(h_) ((h_) >= 2)

#define             g_assert(expr)

//static guint8 message_type = 0;
/* Initialize the protocol and registered fields */

static guint8 message_type = 0;
static guint dlr = 0;
static guint slr = 0;
static gboolean sccp_show_length = FALSE;


/* Declarations to desegment XUDT Messages */
static gboolean sccp_xudt_desegment = TRUE;
static gboolean show_key_params = FALSE;
static gboolean set_addresses = FALSE;

typedef struct dissector_handle *dissector_handle_t;
static dissector_handle_t requested_subdissector_handle = NULL;


static gint ett_sccp_xudt_msg_fragment = -1;
static gint ett_sccp_xudt_msg_fragments = -1;
static int hf_sccp_xudt_msg_fragments = -1;

static int hf_sccp_xudt_msg_fragment = -1;
static int hf_sccp_xudt_msg_fragment_overlap = -1;
static int hf_sccp_xudt_msg_fragment_overlap_conflicts = -1;
static int hf_sccp_xudt_msg_fragment_multiple_tails = -1;
static int hf_sccp_xudt_msg_fragment_too_long_fragment = -1;
static int hf_sccp_xudt_msg_fragment_error = -1;
static int hf_sccp_xudt_msg_fragment_count = -1;
static int hf_sccp_xudt_msg_reassembled_in = -1;
static int hf_sccp_xudt_msg_reassembled_length = -1;
static int hf_sccp_assoc_msg = -1;
static int hf_sccp_assoc_id = -1;

static int hf_sccp_called_ansi_national_indicator = -1;
static int hf_sccp_calling_ansi_national_indicator = -1;

static int hf_sccp_called_itu_natl_use_bit = -1;
static int hf_sccp_calling_itu_natl_use_bit = -1;
static int hf_sccp_called_routing_indicator = -1;
static int hf_sccp_calling_routing_indicator = -1;
static int hf_sccp_called_itu_global_title_indicator = -1;
static int hf_sccp_calling_itu_global_title_indicator = -1;
static int hf_sccp_called_itu_ssn_indicator = -1;
static int hf_sccp_calling_itu_ssn_indicator = -1;

static int hf_sccp_called_itu_point_code_indicator = -1;
static int hf_sccp_calling_itu_point_code_indicator = -1;



static int hf_sccp_called_ssn = -1;
static int hf_sccp_calling_ssn = -1;
static int hf_sccp_called_ansi_ssn_indicator = -1;
static int hf_sccp_calling_ansi_ssn_indicator = -1;

static int hf_sccp_called_ansi_global_title_indicator = -1;
static int hf_sccp_calling_ansi_global_title_indicator = -1;
static int hf_sccp_called_ansi_point_code_indicator = -1;
static int hf_sccp_calling_ansi_point_code_indicator = -1;
static gboolean debug_use_memory_scrubber = FALSE;


typedef struct _value_string {
	guint32  value;
	const gchar   *strptr;
}value_string;

static const value_string sccp_address_signal_values[] = {
	{ 0,  "0" },
	{ 1,  "1" },
	{ 2,  "2" },
	{ 3,  "3" },
	{ 4,  "4" },
	{ 5,  "5" },
	{ 6,  "6" },
	{ 7,  "7" },
	{ 8,  "8" },
	{ 9,  "9" },
	{ 10, "(spare)" },
	{ 11, "11" },
	{ 12, "12" },
	{ 13, "(spare)" },
	{ 14, "(spare)" },
	{ 15, "ST" },
	{ 0,  NULL } };

/* VALUE TO STRING MATCHING */


static const value_string sccp_class_handling_values[] = {
	{ 0x0,  "No special options" },
	{ 0x8,  "Return message on error" },
	{ 0,    NULL } };


const value_string E164_GMSS_vals[] = {
	{ 0x6, "Iridium Satellite LLC" },
	{ 0x7, "Iridium Satellite LLC" },
	{ 0x8, "Globalstar" },
	{ 0x9, "Globalstar" },
	{ 0,	NULL }
};

const value_string E164_International_Networks_883_vals[] = {
	{ 0x100, "MediaLincc Ltd" },
	{ 0x110, "Aicent Inc" },
	{ 0x120, "Telenor Connexion AB" },
	{ 0x130, "France Telecom Orange" },
	{ 0x140, "Multiregional TransitTelecom (MTT)" },
	{ 0x5100, "Voxbone SA" },
	{ 0x5110, "Bandwith.com Inc" },
	{ 0,	NULL }
};

/* Expert Info and Display hf data */
typedef struct _emem_chunk_t {
	struct _emem_chunk_t *next;
	char		*buf;
	unsigned int	amount_free_init;
	unsigned int	amount_free;
	unsigned int	free_offset_init;
	unsigned int	free_offset;
	void		*canary_last;
} emem_chunk_t;

#define EMEM_CANARY_SIZE 8
#define EMEM_CANARY_DATA_SIZE (EMEM_CANARY_SIZE * 2 - 1)
typedef struct _emem_header_t {
	emem_chunk_t *free_list;
	emem_chunk_t *used_list;

	//emem_tree_t *trees;		/* only used by se_mem allocator */

	guint8 canary[EMEM_CANARY_DATA_SIZE];
	void *(*memory_alloc)(size_t size, struct _emem_header_t *);


	gboolean debug_use_chunks;

	gboolean debug_use_canary;

	gboolean debug_verify_pointers;

} emem_header_t;
static emem_header_t ep_packet_mem;

typedef struct expert_field
{
	int ei;
	int hf;
} expert_field;

static expert_field ei_sccp_international_standard_address = EI_INIT;
static expert_field ei_sccp_no_ssn_present = EI_INIT;
static expert_field ei_sccp_ssn_zero = EI_INIT;

static expert_field ei_sccp_class_unexpected = EI_INIT;
#define CLASS_SPARE_HANDLING_MASK       0xf0
static expert_field ei_sccp_handling_invalid = EI_INIT;


typedef void(*tvbuff_free_cb_t)(void*);

/* a function for creating temporary hash keys */
typedef gpointer(*fragment_temporary_key)(
	const guint32 id, const void *data);


/* a function for creating persistent hash keys */
typedef gpointer(*fragment_persistent_key)(
	const guint32 id, const void *data);

typedef struct _DSSSEED {
	DWORD   counter;
	BYTE    seed[20];
} DSSSEED;


typedef struct _GHashTable GHashTable;

typedef struct {
	GHashTable *fragment_table;
	GHashTable *reassembled_table;
	fragment_temporary_key temporary_key_func;
	fragment_persistent_key persistent_key_func;

	//GDestroyNotify free_temporary_key_func;		/* temporary key destruction function */
} reassembly_table;

typedef struct _IMAGE_DELAYLOAD_DESCRIPTOR {
	union {
		DWORD AllAttributes;
		struct {
			DWORD RvaBased : 1;             // Delay load version 2
			DWORD ReservedAttributes : 31;
		};
	} Attributes;

	DWORD DllNameRVA;                       // RVA to the name of the target library (NULL-terminate ASCII string)
	DWORD ModuleHandleRVA;                  // RVA to the HMODULE caching location (PHMODULE)
	DWORD ImportAddressTableRVA;            // RVA to the start of the IAT (PIMAGE_THUNK_DATA)
	DWORD ImportNameTableRVA;               // RVA to the start of the name table (PIMAGE_THUNK_DATA::AddressOfData)
	DWORD BoundImportAddressTableRVA;       // RVA to an optional bound IAT
	DWORD UnloadInformationTableRVA;        // RVA to an optional unload info table
	DWORD TimeDateStamp;                    // 0 if not bound,
											// Otherwise, date/time of the target DLL

} IMAGE_DELAYLOAD_DESCRIPTOR, *PIMAGE_DELAYLOAD_DESCRIPTOR;
//typedef const IMAGE_DELAYLOAD_DESCRIPTOR *PCIMAGE_DELAYLOAD_DESCRIPTOR;

struct GSList {
	gpointer data;
	GSList *next;
};

typedef GSList *heur_dissector_list_t;

static heur_dissector_list_t heur_subdissector_list;

/* WS_DLL_PUBLIC const value_string sccp_message_type_acro_values[];
WS_DLL_PUBLIC const value_string sccp_release_cause_values[];
WS_DLL_PUBLIC const value_string sccp_return_cause_values[];
WS_DLL_PUBLIC const value_string sccp_reset_cause_values[];
WS_DLL_PUBLIC const value_string sccp_error_cause_values[];
WS_DLL_PUBLIC const value_string sccp_refusal_cause_values[]; */

/* WS_DLL_PUBLIC void except_setup_try(struct except_stacknode *,
struct except_catch *, const except_id_t[], size_t);  */

/*WS_DLL_PUBLIC WS_MSVC_NORETURN void except_rethrow(except_t *) G_GNUC_NORETURN;
WS_DLL_PUBLIC WS_MSVC_NORETURN void except_throw(long, long, const char *) G_GNUC_NORETURN;
WS_DLL_PUBLIC WS_MSVC_NORETURN void except_throwd(long, long, const char *, void *) G_GNUC_NORETURN;
WS_DLL_PUBLIC WS_MSVC_NORETURN void except_throwf(long, long, const char *, ...) G_GNUC_NORETURN; */


enum
{
	COL_INFO
};


/* field types */
enum ftenum {
	FT_NONE,	/* used for text labels with no value */
	FT_PROTOCOL,
	FT_BOOLEAN,	/* TRUE and FALSE come from <glib.h> */
	FT_UINT8,
	FT_UINT16,
	FT_UINT24,	/* really a UINT32, but displayed as 3 hex-digits if FD_HEX*/
	FT_UINT32,
	FT_UINT64,
	FT_INT8,
	FT_INT16,
	FT_INT24,	/* same as for UINT24 */
	FT_INT32,
	FT_INT64,
	FT_FLOAT,
	FT_DOUBLE,
	FT_ABSOLUTE_TIME,
	FT_RELATIVE_TIME,
	FT_STRING,
	FT_STRINGZ,	/* for use with proto_tree_add_item() */
	FT_UINT_STRING,	/* for use with proto_tree_add_item() */
					/*FT_UCS2_LE, */    /* Unicode, 2 byte, Little Endian     */
					FT_ETHER,
					FT_BYTES,
					FT_UINT_BYTES,
					FT_IPv4,
					FT_IPv6,
					FT_IPXNET,
					FT_FRAMENUM,	/* a UINT32, but if selected lets you go to frame with that number */
					FT_PCRE,	/* a compiled Perl-Compatible Regular Expression object */
					FT_GUID,	/* GUID, UUID */
					FT_OID,		/* OBJECT IDENTIFIER */
					FT_EUI64,
					FT_AX25,
					FT_VINES,
					FT_NUM_TYPES /* last item number plus one */
};


typedef enum {
	HF_REF_TYPE_NONE,       /**< Field is not referenced */
	HF_REF_TYPE_INDIRECT,   /**< Field is indirectly referenced (only applicable for FT_PROTOCOL) via. its child */
	HF_REF_TYPE_DIRECT      /**< Field is directly referenced */
} hf_ref_type;




static const value_string hf_types[] = {
	{ FT_NONE,	    "FT_NONE" },
	{ FT_PROTOCOL,	    "FT_PROTOCOL" },
	{ FT_BOOLEAN,	    "FT_BOOLEAN" },
	{ FT_UINT8,	    "FT_UINT8" },
	{ FT_UINT16,	    "FT_UINT16" },
	{ FT_UINT24,	    "FT_UINT24" },
	{ FT_UINT32,	    "FT_UINT32" },
	{ FT_UINT64,	    "FT_UINT64" },
	{ FT_INT8,	    "FT_INT8" },
	{ FT_INT16,	    "FT_INT16" },
	{ FT_INT24,	    "FT_INT24" },
	{ FT_INT32,	    "FT_INT32" },
	{ FT_INT64,	    "FT_INT64" },
	{ FT_EUI64,	    "FT_EUI64" },
	{ FT_FLOAT,	    "FT_FLOAT" },
	{ FT_DOUBLE,	    "FT_DOUBLE" },
	{ FT_ABSOLUTE_TIME, "FT_ABSOLUTE_TIME" },
	{ FT_RELATIVE_TIME, "FT_RELATIVE_TIME" },
	{ FT_STRING,	    "FT_STRING" },
	{ FT_STRINGZ,	    "FT_STRINGZ" },
	{ FT_UINT_STRING,   "FT_UINT_STRING" },
	{ FT_ETHER,	    "FT_ETHER" },
	{ FT_BYTES,	    "FT_BYTES" },
	{ FT_UINT_BYTES,    "FT_UINT_BYTES" },
	{ FT_IPv4,	    "FT_IPv4" },
	{ FT_IPv6,	    "FT_IPv6" },
	{ FT_IPXNET,	    "FT_IPXNET" },
	{ FT_FRAMENUM,	    "FT_FRAMENUM" },
	{ FT_PCRE,	    "FT_PCR" },
	{ FT_GUID,	    "FT_GUID" },
	{ FT_OID,	    "FT_OID" },
	{ 0,		    NULL } };



//WS_DLL_PUBLIC const value_string mtp3_service_indicator_code_short_vals[];

const value_string sccp_message_type_acro_values[] = {
	{ SCCP_MSG_TYPE_CR,           "CR" },
	{ SCCP_MSG_TYPE_CC,           "CC" },
	{ SCCP_MSG_TYPE_CREF,         "CREF" },
	{ SCCP_MSG_TYPE_RLSD,         "RLSD" },
	{ SCCP_MSG_TYPE_RLC,          "RLC" },
	{ SCCP_MSG_TYPE_DT1,          "DT1" },
	{ SCCP_MSG_TYPE_DT2,          "DT2" },
	{ SCCP_MSG_TYPE_AK,           "AK" },
	{ SCCP_MSG_TYPE_UDT,          "UDT" },
	{ SCCP_MSG_TYPE_UDTS,         "UDTS" },
	{ SCCP_MSG_TYPE_ED,           "ED" },
	{ SCCP_MSG_TYPE_EA,           "EA" },
	{ SCCP_MSG_TYPE_RSR,          "RSR" },
	{ SCCP_MSG_TYPE_RSC,          "RSC" },
	{ SCCP_MSG_TYPE_ERR,          "ERR" },
	{ SCCP_MSG_TYPE_IT,           "IT" },
	{ SCCP_MSG_TYPE_XUDT,         "XUDT" },
	{ SCCP_MSG_TYPE_XUDTS,        "XUDTS" },
	{ SCCP_MSG_TYPE_LUDT,         "LUDT" },
	{ SCCP_MSG_TYPE_LUDTS,        "LUDTS" },
	{ 0,                          NULL } };

/* Same as above but in acronym form (for the Info column) */


/* String representation types. */
enum ftrepr {
	FTREPR_DISPLAY,
	FTREPR_DFILTER
};

typedef enum ftrepr ftrepr_t;

typedef struct _reassembled_key {
	guint32 id;
	guint32 frame;
} reassembled_key;

struct GByteArray {
	guint8 *data;
	guint	  len;
};

typedef struct {
	guint32	addr;	/* stored in host order */
	guint32	nmask;	/* stored in host order */
} ipv4_addr;

struct e_in6_addr {
	guint8   bytes[16];		/**< 128 bit IP6 address */
};


typedef struct {
	struct e_in6_addr addr;
	guint32 prefix;
} ipv6_addr;

typedef struct _e_guid_t {
	guint32 data1;
	guint16 data2;
	guint16 data3;
	guint8  data4[8];
} e_guid_t;

/** information describing a header field */
typedef struct _header_field_info header_field_info;

struct _header_field_info {
	/* ---------- set by dissector --------- */
	const char		*name;           /**< [FIELDNAME] full name of this field */
	const char		*abbrev;         /**< [FIELDABBREV] abbreviated name of this field */
	enum ftenum		 type;           /**< [FIELDTYPE] field type, one of FT_ (from ftypes.h) */
	int			 display;        /**< [FIELDDISPLAY] one of BASE_, or field bit-width if FT_BOOLEAN and non-zero bitmask */
	const void		*strings;        /**< [FIELDCONVERT] value_string, range_string or true_false_string,
									 typically converted by VALS(), RVALS() or TFS().
									 If this is an FT_PROTOCOL then it points to the
									 associated protocol_t structure */
	guint32			 bitmask;        /**< [BITMASK] bitmask of interesting bits */
	const char		*blurb;          /**< [FIELDDESCR] Brief description of field */

									 /* ------- set by proto routines (prefilled by HFILL macro, see below) ------ */
	int			 id;             /**< Field ID */
	int			 parent;         /**< parent protocol tree */
	hf_ref_type		 ref_type;       /**< is this field referenced by a filter */
	int same_name_prev_id; /**< ID of previous hfinfo with same abbrev */
	header_field_info *same_name_next; /**< Link to next hfinfo with same abbrev */
};



/** information describing a header field */


typedef struct hf_register_info {
	int				*p_id;	/**< written to by register() function */
	header_field_info		hfinfo;	/**< the field info to be registered */
} hf_register_info;


typedef struct _sccp_msg_info_t {
	guint framenum;
	guint offset;
	guint type;

	union {
		struct {
			gchar* label;
			gchar* comment;
			struct _sccp_assoc_info_t* assoc;
			struct _sccp_msg_info_t* next;
		} co;
		struct {
			guint8* calling_gt;
			guint calling_ssn;
			guint8* called_gt;
			guint called_ssn;
		} ud;
	} data;
} sccp_msg_info_t;

static sccp_msg_info_t   *sccp_msg;



typedef enum _sccp_payload_t {
	SCCP_PLOAD_NONE,
	SCCP_PLOAD_BSSAP,
	SCCP_PLOAD_RANAP,
	SCCP_PLOAD_NUM_PLOADS
} sccp_payload_t;


typedef struct _sccp_assoc_info_t {
	guint32 id;
	guint32 calling_dpc;
	guint32 called_dpc;
	guint8 calling_ssn;
	guint8 called_ssn;
	gboolean has_fw_key;
	gboolean has_bw_key;
	sccp_msg_info_t* msgs;
	sccp_msg_info_t* curr_msg;

	sccp_payload_t payload;
	gchar* calling_party;
	gchar* called_party;
	gchar* extra_info;
	guint32 app_info;  /* used only by dissectors of protocols above SCCP */

} sccp_assoc_info_t;

//WS_DLL_PUBLIC guint8  tvb_get_guint8(tvbuff_t*, const gint offset);


typedef struct SS7_target
{

	char* calledParty_no;
	char* callingParty_no;

};



/*
* Tvbuff flags.
*/
#define TVBUFF_FRAGMENT		0x00000001	/* this is a fragment */
#define ITEM_LABEL_LENGTH	240

#define REASSEMBLE_FLAGS_NO_FRAG_NUMBER		0x0001
#define REASSEMBLE_FLAGS_CHECK_DATA_PRESENT	0x0004
#define FD_DATA_NOT_PRESENT	0x0200
#define FD_DEFRAGMENTED		0x0001
#define REASSEMBLE_FLAGS_802_11_HACK		0x0002
#define FD_BLOCKSEQUENCE        0x0100
#define FD_PARTIAL_REASSEMBLY   0x0040
#define FD_OVERLAP		0x0002

#define FD_SUBSET_TVB           0x0020
#define FD_TOOLONGFRAGMENT	0x0010
#define FD_MULTIPLETAILS	0x0008
#define FD_DATALEN_SET		0x0400
#define FD_OVERLAPCONFLICT	0x0004

#define GTI_SHIFT                       2
#define AI_GTI_TT                       0x2
#define ITU_AI_GTI_TT_NP_ES_NAI 0x4
#define ITU_AI_GTI_TT_NP_ES             0x3
#define ANSI_AI_GTI_TT_NP_ES    0x1
#define GT_TT_LENGTH 1

#define GT_NP_MASK              0xf0
#define GT_ES_MASK     0x0f
#define GT_NP_ES_LENGTH         1
#define GT_ES_BCD_EVEN 0x2
#define ITU_AI_GTI_NAI                  0x1
#define GT_OE_MASK 0x80
#define GT_OE_EVEN 0
#define GT_NAI_MASK 0x7F
#define GT_NAI_LENGTH 1
#define GT_NP_SHIFT             4
#define GT_NP_ISDN              0x01
#define GT_NP_ISDN_MOBILE       0x07
#define GT_NAI_INTERNATIONAL_NUM        0x04

struct tvbuff;
typedef struct tvbuff tvbuff_t;

struct tvb_ops {
	gsize tvb_size;
	void(*tvb_free)(struct tvbuff *tvb);
	guint(*tvb_offset)(const struct tvbuff *tvb, guint counter);
	const guint8 *(*tvb_get_ptr)(struct tvbuff *tvb, guint abs_offset, guint abs_length);
	void *(*tvb_memcpy)(struct tvbuff *tvb, void *target, guint offset, guint length);

	gint(*tvb_find_guint8)(tvbuff_t *tvb, guint abs_offset, guint limit, guint8 needle);
	gint(*tvb_pbrk_guint8)(tvbuff_t *tvb, guint abs_offset, guint limit, const guint8 *needles, guchar *found_needle);

	tvbuff_t *(*tvb_clone)(tvbuff_t *tvb, guint abs_offset, guint abs_length);
};


struct tvbuff {
	/* Doubly linked list pointers */
	tvbuff_t *next;

	/* Record-keeping */
const struct tvb_ops   *ops;
	gboolean		initialized;
	guint			flags;
	struct tvbuff		*ds_tvb;  /**< data source top-level tvbuff */

								  /** We're either a TVBUFF_REAL_DATA or a
								  * TVBUFF_SUBSET that has a backing buffer that
								  * has real_data != NULL, or a TVBUFF_COMPOSITE
								  * which has flattened its data due to a call
								  * to tvb_get_ptr().
								  */
	const guint8		*real_data;

	/** Length of virtual buffer (and/or real_data). */
	guint length;

	/** Reported length. */
	guint			reported_length;

	/* Offset from beginning of first TVBUFF_REAL. */
	gint			raw_offset;
};






typedef enum ftenum ftenum_t;
typedef struct _ftype_t ftype_t;

typedef struct _fvalue_t {
	ftype_t	*ftype;
	union {
		/* Put a few basic types in here */
		guint32		uinteger;
		gint32		sinteger;
		guint64		integer64;
		gdouble		floating;
		gchar		*string;
		guchar		*ustring;
		GByteArray	*bytes;
		ipv4_addr	ipv4;
		ipv6_addr	ipv6;
		e_guid_t	guid;
		//nstime_t	time;
		tvbuff_t	*tvb;
		//GRegex	        *re;
	} value;

	/* The following is provided for private use
	* by the fvalue. */
	gboolean	fvalue_gboolean1;

} fvalue_t;




typedef void(*FvalueNewFunc)(fvalue_t*);
typedef void(*FvalueFreeFunc)(fvalue_t*);
typedef void(*LogFunc)(const char*, ...);

typedef gboolean(*FvalueFromUnparsed)(fvalue_t*, char*, gboolean, LogFunc);
typedef gboolean(*FvalueFromString)(fvalue_t*, char*, LogFunc);
typedef void(*FvalueToStringRepr)(fvalue_t*, ftrepr_t, char*volatile);
typedef int(*FvalueStringReprLen)(fvalue_t*, ftrepr_t);

typedef void(*FvalueSetFunc)(fvalue_t*, gpointer, gboolean);
typedef void(*FvalueSetUnsignedIntegerFunc)(fvalue_t*, guint32);
typedef void(*FvalueSetSignedIntegerFunc)(fvalue_t*, gint32);
typedef void(*FvalueSetInteger64Func)(fvalue_t*, guint64);
typedef void(*FvalueSetFloatingFunc)(fvalue_t*, gdouble);

typedef gpointer(*FvalueGetFunc)(fvalue_t*);
typedef guint32(*FvalueGetUnsignedIntegerFunc)(fvalue_t*);
typedef gint32(*FvalueGetSignedIntegerFunc)(fvalue_t*);
typedef guint64(*FvalueGetInteger64Func)(fvalue_t*);
typedef double(*FvalueGetFloatingFunc)(fvalue_t*);

typedef gboolean(*FvalueCmp)(const fvalue_t*, const fvalue_t*);

typedef guint(*FvalueLen)(fvalue_t*);
typedef void(*FvalueSlice)(fvalue_t*, GByteArray *, guint offset, guint length);

/** string representation, if one of the proto_tree_add_..._format() functions used */
typedef struct _item_label_t {
	char representation[ITEM_LABEL_LENGTH];
} item_label_t;




struct _ftype_t {
	ftenum_t		ftype;
	const char		*name;
	const char		*pretty_name;
	int			wire_size;
	FvalueNewFunc		new_value;
	FvalueFreeFunc		free_value;
	FvalueFromUnparsed	val_from_unparsed;
	FvalueFromString	val_from_string;
	FvalueToStringRepr	val_to_string_repr;
	FvalueStringReprLen	len_string_repr;

	/* could be union */
	FvalueSetFunc		set_value;
	FvalueSetUnsignedIntegerFunc	set_value_uinteger;
	FvalueSetSignedIntegerFunc		set_value_sinteger;
	FvalueSetInteger64Func	set_value_integer64;
	FvalueSetFloatingFunc	set_value_floating;

	/* could be union */
	FvalueGetFunc		get_value;
	FvalueGetUnsignedIntegerFunc	get_value_uinteger;
	FvalueGetSignedIntegerFunc		get_value_sinteger;
	FvalueGetInteger64Func	get_value_integer64;
	FvalueGetFloatingFunc	get_value_floating;

	FvalueCmp		cmp_eq;
	FvalueCmp		cmp_ne;
	FvalueCmp		cmp_gt;
	FvalueCmp		cmp_ge;
	FvalueCmp		cmp_lt;
	FvalueCmp		cmp_le;
	FvalueCmp		cmp_bitwise_and;
	FvalueCmp		cmp_contains;
	FvalueCmp		cmp_matches;

	FvalueLen		len;
	FvalueSlice		slice;
};








typedef struct field_info {
	header_field_info	*hfinfo;          /**< pointer to registered field information */
	gint			 start;           /**< current start of data in field_info.ds_tvb */
	gint			 length;          /**< current data length of item in field_info.ds_tvb */
	gint			 appendix_start;  /**< start of appendix data */
	gint			 appendix_length; /**< length of appendix data */
	gint			 tree_type;       /**< one of ETT_ or -1 */
	guint32			 flags;           /**< bitfield like FI_GENERATED, ... */
	item_label_t		*rep;             /**< string for GUI tree */
	tvbuff_t		*ds_tvb;          /**< data source tvbuff */
	fvalue_t		 value;
} field_info;

typedef struct _proto_node {
	struct _proto_node *first_child;
	struct _proto_node *last_child;
	struct _proto_node *next;
	struct _proto_node *parent;
	field_info  *finfo;
	//tree_data_t *tree_data;
} proto_node;

/** Retrieve the field_info from a proto_node */
#define PNODE_FINFO(proto_node)  ((proto_node)->finfo)

/** Retrieve the field_info from a proto_item */
#define PITEM_FINFO(proto_item)  PNODE_FINFO(proto_item)


/** A protocol tree element. */
typedef proto_node proto_tree;
typedef proto_node proto_item;

typedef enum {
	ITU_STANDARD = 1,
	ANSI_STANDARD = 2,
	CHINESE_ITU_STANDARD = 3,
	JAPAN_STANDARD = 4
} Standard_Type;

static Standard_Type decode_mtp3_standard;


typedef struct _mtp3_addr_pc_t {
	Standard_Type		type;
	guint32		pc;
	guint8		ni;
} mtp3_addr_pc_t;


typedef struct _fragment_item {
	struct _fragment_item *next;
	guint32 frame;	/* XXX - does this apply to reassembly heads? */
	guint32	offset;	/* XXX - does this apply to reassembly heads? */
	guint32	len;	/* XXX - does this apply to reassembly heads? */
	guint32 fragment_nr_offset; /* offset for frame numbering, for sequences, where the
								* provided fragment number of the first fragment does
								* not start with 0
								* XXX - does this apply only to reassembly heads? */
	guint32 datalen; /* Only valid in first item of list and when
					 * flags&FD_DATALEN_SET is set;
					 * number of bytes or (if flags&FD_BLOCKSEQUENCE set)
					 * segments in the datagram */
	guint32 reassembled_in;	/* frame where this PDU was reassembled,
							only valid in the first item of the list
							and when FD_DEFRAGMENTED is set*/
	guint32 flags;	/* XXX - do some of these apply only to reassembly
					heads and others only to fragments within
					a reassembly? */
	tvbuff_t *tvb_data;

	/*
	* Null if the reassembly had no error; non-null if it had
	* an error, in which case it's the string for the error.
	*
	* XXX - this is wasted in all but the reassembly head; we
	* should probably have separate data structures for a
	* reassembly and for the fragments in a reassembly.
	*/
	const char *error;
} fragment_item, fragment_head;

typedef struct _fragment_items {
	gint       *ett_fragment;
	gint       *ett_fragments;

	int        *hf_fragments;                  /* FT_BOOLEAN  */
	int        *hf_fragment;                   /* FT_FRAMENUM */
	int        *hf_fragment_overlap;           /* FT_BOOLEAN  */
	int        *hf_fragment_overlap_conflict;  /* FT_BOOLEAN  */
	int        *hf_fragment_multiple_tails;    /* FT_BOOLEAN  */
	int        *hf_fragment_too_long_fragment; /* FT_BOOLEAN  */
	int        *hf_fragment_error;             /* FT_FRAMENUM */
	int        *hf_fragment_count;             /* FT_UINT32   */
	int        *hf_reassembled_in;             /* FT_FRAMENUM */
	int        *hf_reassembled_length;         /* FT_UINT32   */
	int        *hf_reassembled_data;           /* FT_BYTES    */

	const char *tag;
} fragment_items;


static const fragment_items sccp_xudt_msg_frag_items = {
	/* Fragment subtrees */
	&ett_sccp_xudt_msg_fragment,
	&ett_sccp_xudt_msg_fragments,
	/* Fragment fields */
	&hf_sccp_xudt_msg_fragments,
	&hf_sccp_xudt_msg_fragment,
	&hf_sccp_xudt_msg_fragment_overlap,
	&hf_sccp_xudt_msg_fragment_overlap_conflicts,
	&hf_sccp_xudt_msg_fragment_multiple_tails,
	&hf_sccp_xudt_msg_fragment_too_long_fragment,
	&hf_sccp_xudt_msg_fragment_error,
	&hf_sccp_xudt_msg_fragment_count,
	/* Reassembled in field */
	&hf_sccp_xudt_msg_reassembled_in,
	/* Reassembled length field */
	&hf_sccp_xudt_msg_reassembled_length,
	/* Reassembled data field */
	NULL,
	/* Tag */
	"SCCP XUDT Message fragments"
};


struct tvb_real {
	struct tvbuff tvb;

	/** Func to call when actually freed */
	tvbuff_free_cb_t	free_cb;
};


typedef struct {
	/** The backing tvbuff_t */
	struct tvbuff	*tvb;

	/** The offset of 'tvb' to which I'm privy */
	guint		offset;
	/** The length of 'tvb' to which I'm privy */
	guint		length;

} tvb_backing_t;

struct tvb_subset {
	struct tvbuff tvb;

	tvb_backing_t	subset;
};



/* Structure for information about a protocol */
struct _protocol {
	const char *name;         /* long description */
	const char *short_name;   /* short description */
	const char *filter_name;  /* name of this protocol in filters */
	int         proto_id;     /* field ID for this protocol */
	GSList     *fields;       /* fields for this protocol */
	GSList     *last_field;   /* pointer to end of list of fields */
	gboolean    is_enabled;   /* TRUE if protocol is enabled */
	gboolean    can_toggle;   /* TRUE if is_enabled can be changed */
	gboolean    is_private;   /* TRUE is protocol is private */
};


typedef struct _protocol protocol_t;






struct dissector_handle {
	const char	*name;		/* dissector name */
	gboolean	is_new;		/* TRUE if new-style dissector */
	union {
		//dissector_t	old;
		//new_dissector_t	new_d;
	} dissector;
	protocol_t	*protocol;
};

typedef struct dissector_handle *dissector_handle_t;
static dissector_handle_t default_handle;
static dissector_handle_t data_handle = NULL;

typedef struct range_admin_tag {
	guint32 low;
	guint32 high;
} range_admin_t;

/** user specified range(s) */
typedef struct range {
	guint           nranges;   /**< number of entries in ranges */
	range_admin_t   ranges[1]; /**< variable-length array */
} range_t;

typedef struct _sccp_user_t {
	guint               ni;
	range_t            *called_pc;
	range_t            *called_ssn;
	guint               user;
	gboolean            uses_tcap;
	dissector_handle_t *handlep;
} sccp_user_t;

static sccp_user_t *sccp_users;
static guint        num_sccp_users;

struct dissector_table {
	GHashTable	*hash_table;
	GSList		*dissector_handles;
	const char	*ui_name;
	ftenum_t	type;
	int		base;
};

typedef struct dissector_table *dissector_table_t;
static dissector_table_t sccp_ssn_dissector_table;

typedef gboolean(*heur_dissector_t)(tvbuff_t *tvb,
	proto_tree *tree, void *);

struct dtbl_entry {
	dissector_handle_t initial;
	dissector_handle_t current;
};

typedef struct {
	heur_dissector_t dissector;
	protocol_t *protocol;
	gboolean enabled;
} heur_dtbl_entry_t;

typedef struct dtbl_entry dtbl_entry_t;
dtbl_entry_t *dtbl_entry;

typedef struct expert_field_info {
	/* ---------- set by dissector --------- */
	const char *name;
	int group;
	int severity;
	const gchar *summary;

	/* ------- set by register routines (prefilled by EXPFILL macro, see below) ------ */
	int id;
	const gchar *protocol;
	hf_register_info hf_info;

} expert_field_info;
