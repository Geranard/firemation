from django import template

register = template.Library()

@register.filter
def get_type(value):
    if("str" in str(type(value))):
        return "str"
    elif("list" in str(type(value))):
        return "list"

@register.filter
def get_length(value):
    return len(value)