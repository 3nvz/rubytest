module LogUtils
  def self.search_logs(term)
    run_command(term)
  end

  def self.run_command(term)
    cmd = "grep -R #{term} logs/"
    `#{cmd}`
  end
end