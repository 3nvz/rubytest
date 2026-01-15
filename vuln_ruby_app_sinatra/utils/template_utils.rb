require "erb"

module TemplateUtils
  def self.render_template(user_template)
    evaluate_template(user_template)
  end

  def self.evaluate_template(tpl)
    ERB.new(tpl).result(binding)
  end
end