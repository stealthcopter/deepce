---
page: default
title: tests
permalink: /tests/
---

# Tests

{% assign image_files = site.static_files | where: "test", true %}
{% for myimage in image_files %}
  {{ myimage.path }}
{% endfor %}
