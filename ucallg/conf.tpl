/* #define CIRCBUF_BITS 12 */
/* #define CTXTABLE_BITS 12 */
/* #define DEBUG */

#define A 0
#define D 1
/* #define FILTER_POLICY AD */
{% for path, funs in libs.items() %}

/*{{ '{:-^80}'.format(path) }}*/
    {% for offset, name in funs.items() %}
/* {{ name.real }} */
/* #define FILTER_RULE_{{ name.alias }} AD */
    {% endfor %}
{% endfor %}
