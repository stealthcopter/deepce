# Guides

This folder contains a set of guides that explain about container enumerations and exploits. When `deepce.sh` detects something exploitable or there is more information that is too verbose to explain in a message in the console we will link to a guide here.

<div class="cupcakes">
<ul>
{% for file in site.static_files %}
    {% if file.path contains 'guides/' %}
        {% unless file.path contains 'README.md' or file.path contains 'template.md' %}
            <li><a href="{{file.path| split:"." | first}}">{{file.path | split:"/" | last | split:"." | first}}</a></li>
        {% endunless %}
    {% endif %}
{% endfor %}
</ul>
</div>

## Contributing
To add a new guide please start from the [template](template)
