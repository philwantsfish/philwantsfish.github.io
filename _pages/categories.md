---
permalink: posts
---
<html>
  {% include header.html %}
  <body>
    {% include navigation.html %}

    <div class="col-md-3"></div>
    
    <div class="container-fluid">
      <div class="col-md-6">
        <h1>Posts</h1>
        <p>sorted by categories</p>
        <hr/>
        
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
      </div>
    </div>
        
        
    <div class="col-md-3"> </div>

    {% include footer.html %}
  </body>
</html>