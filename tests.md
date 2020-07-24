---
page: default
title: tests
permalink: /tests/
---

# Tests


aaaa

{% assign image_files = site.static_files | where: "test", true %}
{% for myimage in image_files %}
  {{ myimage.path }}
{% endfor %}

bbb

{% for file in site.static_files %}
    {{ file.path }}
{% endif %}

ccc

{% for page in site.tests %}
<h3><a title="{{ page.title }}" href="{{ page.url | prepend: site.baseurl }}">{{ page.title }}</a></h3>
<p>{{page.content}}</p>
{% endfor %}     
