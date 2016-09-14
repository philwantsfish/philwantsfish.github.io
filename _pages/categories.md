---
title: Blogging like a salmon
permalink: posts
---
<html>
  {% include header.html %}
  
  <body>
    {% include navigation.html %}

    <div class="container">
      <div class="col-md-8">
        <div class="row">
          {% for category in site.categories %}
            <a href="#{{ category | first }}"></a><p class="lead">{{ category | first }}</p>
            <hr/>
            <ul>
            {% for posts in category %}
              {% for post in posts %}
                {% if post.url %}
                <li><a href="{{ post.url }}">{{ post.title }}</a></li>
                {% endif %}
              {% endfor %}
            {% endfor %}
            </ul>
          {% endfor %}
        </div>
      </div> <!-- end of col-md-8 -->
      <div class="col-md-4">
        {% include sidebar.html %}
      </div> <!-- end of col-md-4 -->
    </div> <!-- end of container -->

    {% include footer.html %}
  </body>
</html>
