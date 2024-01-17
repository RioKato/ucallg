#define DEBUG 1
#define A 0
#define D 1

#if __has_include("{{ autoconfig }}")
#    include "{{ autoconfig }}"
#endif

/* #define CIRCBUF_BITS 12 */
/* #define CTXTABLE_BITS 12 */
/* #define MSG_MAXSZ 0x400 */
/* #define CHECK_DEPRECATED */
/* #define FILTER_COVERAGE */
/* #define FILTER_MAX_DEPTH 0 */
/* #define FILTER_POLICY AD */
{% for path, funs in libs.items() %}

/*{{ '{:-^80}'.format(path) }}*/
    {% for offset, name in funs.items() %}
/* {{ name.real }} */
/*     #define FILTER_RULE_{{ name.alias }} AD */
/*     #define URETPROBE_DISABLE_{{ name.alias }} */
    {% endfor %}
{% endfor %}
