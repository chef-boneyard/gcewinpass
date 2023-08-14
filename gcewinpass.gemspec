# coding: utf-8

lib = File.expand_path("../lib", __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)

require "gcewinpass/version"

Gem::Specification.new do |spec|
  spec.name          = "gcewinpass"
  spec.version       = GoogleComputeWindowsPassword::VERSION
  spec.authors       = ["Chef Partner Engineering"]
  spec.email         = ["partnereng@chef.io"]

  spec.summary       = "Reset a password on a Google Compute Engine instance running Windows."
  spec.description   = spec.summary
  spec.homepage      = "https://github.com/chef-partners/gcewinpass"

  spec.files         = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  spec.require_paths = ["lib"]

  spec.add_dependency "google-apis-compute_v1", ">= 0.75"
end
