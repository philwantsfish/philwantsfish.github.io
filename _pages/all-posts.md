---
permalink: notused
---
# This is not used, all posts are shown by categories.md
<html>
  {% include header.html %}
  
  <body>
    {% include navigation.html %}

    <div class="container">
      <div class="col-md-3"> </div>
      <div class="col-md-6">
        <h1>Latest Posts</h1>
        <hr/>

        {% for post in site.posts %}
        <article>
          <h2><a href="{{ post.url }}">{{ post.title }}</a></h2>
       
          <div class="row">
              <div class="group1 col-sm-6 col-md-6">
                {% for tag in post.tags %}
                  <a href="{{tag}}">{{ tag }}</a>
                {% endfor %}
              </div>
              <div class="group2 col-sm-6 col-md-6">
                <span class="glyphicon glyphicon-time"></span> {{ post.date | date_to_long_string }}
              </div>
          </div>
       
          <hr>
          <br />
          <p class="lead">{{ post.excerpt }}</p>

          <p class="pull-right">
              <a href="{{ post.url }}" class="pull-right">
                  continue reading...
              </a>
          </p>
          <hr>
        </article>
        {% endfor %}
      </div>
      <div class="col-md-3"> </div>
    </div> <!-- end of container -->

    {% include footer.html %}
  </body>
</html>
