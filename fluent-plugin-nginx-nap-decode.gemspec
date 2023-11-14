lib = File.expand_path("../lib", __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)

Gem::Specification.new do |spec|
  spec.name    = "fluent-plugin-nginx-nap-decode"
  spec.version = "0.4.61"
  spec.authors = ["Kostas Skenderidis"]
  spec.email   = ["skenderidis@gmail.com"]

  spec.summary       = "Decode the base64 values that are included on the NAP logs"
  spec.homepage      = "https://github.com/skenderidis/fluent-plugin-nginx-nap-decode"
  spec.license       = "Apache-2.0"
  spec.files         = `git ls-files`.split("\n")
  spec.test_files    = `git ls-files -- test/*`.split("\n")
  spec.require_paths = ["lib"]


#  test_files, files  = `git ls-files -z`.split("\x0").partition do |f|
#    f.match(%r{^(test|spec|features)/})
#  end
#  spec.files         = files
#  spec.executables   = files.grep(%r{^bin/}) { |f| File.basename(f) }
#  spec.test_files    = test_files
#  spec.require_paths = ["lib"]

#  spec.add_development_dependency "bundler", "~> 2.4.10"
#  spec.add_development_dependency "rake", "~> 13.0.6"
#  spec.add_development_dependency "test-unit", "~> 3.5.7"
  spec.add_runtime_dependency "fluentd", [">= 0.14.10", "< 2"]
end
