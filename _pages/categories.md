---
permalink: posts
layout: main
---

<div class="row">
  <div class="col-md-12">
    <div class="jumbotron">
      <h1>Posts</h1>
      <p>The collection of blogs posts sorted by category</p>
    </div>
  </div>
</div>

{% for category in site.categories %}
<div class="row">
  <div class="col-md-4">
    <a href="#{{ category | first }}"></a><h2>{{ category | first }}</h2>
  </div>
  <div class="col-md-8">
    <br/>
    <ul>
    {% for posts in category %}
      {% for post in posts %}
        {% if post.url %}
        <li><a href="{{ post.url }}">{{ post.title }}</a></li>
        {% endif %}
      {% endfor %}
    {% endfor %}
    </ul>
  </div>
</div>
<hr/>
{% endfor %} 
