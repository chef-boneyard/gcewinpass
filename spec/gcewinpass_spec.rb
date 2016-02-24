#
# Author:: Chef Partner Engineering (<partnereng@chef.io>)
# Copyright:: Copyright (c) 2016 Chef Software, Inc.
# License:: Apache License, Version 2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

require "gcewinpass"

describe GoogleComputeWindowsPassword do
  let(:project)       { "test_project" }
  let(:zone)          { "test_zone" }
  let(:instance_name) { "test_instance" }
  let(:username)      { "test_username" }
  let(:email)         { "test_email" }

  let(:options) do
    {
      project:       project,
      zone:          zone,
      instance_name: instance_name,
      username:      username,
      email:         email,
    }
  end

  let(:tester) { GoogleComputeWindowsPassword.new(options) }

  before do
    allow(Google::Auth).to receive(:get_application_default)
  end

  describe '#initialize' do
    let(:tester) { GoogleComputeWindowsPassword.allocate }
    let(:api) { double("api") }

    before do
      allow(tester).to receive(:validate_options!)
      allow(tester).to receive(:authorization)
      allow(Google::Apis::ComputeV1::ComputeService).to receive(:new).and_return(api)
      allow(api).to receive(:authorization=)
    end

    it "validates the options" do
      expect(tester).to receive(:validate_options!).with(test: true)
      tester.send(:initialize, test: true)
    end

    it "creates an API instance and configured the authorization" do
      expect(tester).to receive(:authorization).and_return("auth_object")
      expect(Google::Apis::ComputeV1::ComputeService).to receive(:new).and_return(api)
      expect(api).to receive(:authorization=).with("auth_object")
      tester.send(:initialize)
      expect(tester.api).to eq(api)
    end

    it "sets the correct instance variables" do
      tester.send(:initialize, options)

      expect(tester.project).to eq(project)
      expect(tester.zone).to eq(zone)
      expect(tester.instance_name).to eq(instance_name)
      expect(tester.username).to eq(username)
      expect(tester.email).to eq(email)
    end
  end

  describe '#new_password' do
    it "raises an exception if the instance does not exist" do
      expect(tester).to receive(:instance_exists?).and_return(false)
      expect { tester.new_password }.to raise_error(RuntimeError)
    end

    it "calls the correct methods to retrieve the password" do
      expect(tester).to receive(:instance_exists?).and_return(true)
      expect(tester).to receive(:update_instance_metadata)
      expect(tester).to receive(:password_from_instance).and_return("password")
      expect(tester.new_password).to eq("password")
    end
  end

  describe '#validate_options!' do
    it "does not raise an exception with all options exist" do
      expect { tester.validate_options!(options) }.not_to raise_error
    end

    it "raises an exception when project is missing" do
      options.delete(:project)
      expect { tester.validate_options!(options) }.to raise_error(RuntimeError)
    end

    it "raises an exception when zone is missing" do
      options.delete(:zone)
      expect { tester.validate_options!(options) }.to raise_error(RuntimeError)
    end

    it "raises an exception when instance_name is missing" do
      options.delete(:instance_name)
      expect { tester.validate_options!(options) }.to raise_error(RuntimeError)
    end

    it "raises an exception when email is missing" do
      options.delete(:email)
      expect { tester.validate_options!(options) }.to raise_error(RuntimeError)
    end
  end

  describe '#authorization' do
    it "returns a Google::Auth object" do
      expect(Google::Auth).to receive(:get_application_default).and_return("auth_object")
      expect(tester.authorization).to eq("auth_object")
    end
  end

  describe '#instance' do
    it "returns an instance object" do
      api = double("api")
      expect(tester).to receive(:api).and_return(api)
      expect(api).to receive(:get_instance).with(project, zone, instance_name).and_return("test_instance")
      expect(tester.instance).to eq("test_instance")
    end
  end

  describe '#instance_exists?' do
    it "returns false if the API returns an error" do
      expect(tester).to receive(:instance).and_raise(Google::Apis::ClientError.new("error text"))
      expect(tester.instance_exists?).to eq(false)
    end

    it "returns true if the API returns cleanly" do
      expect(tester).to receive(:instance).and_return("instance")
      expect(tester.instance_exists?).to eq(true)
    end
  end

  describe '#instance_metadata' do
    it "returns instance metadata" do
      instance = double("instance")
      expect(tester).to receive(:instance).and_return(instance)
      expect(instance).to receive(:metadata).and_return("test_metadata")
      expect(tester.instance_metadata).to eq("test_metadata")
    end
  end

  describe '#password_request_metadata' do
    it "returns a metadata item" do
      item = double("item")
      expect(tester).to receive(:password_request).and_return(key: "value")
      expect(Google::Apis::ComputeV1::Metadata::Item).to receive(:new).and_return(item)
      expect(item).to receive(:key=).with("windows-keys")
      expect(item).to receive(:value=).with('{"key":"value"}')
      expect(tester.password_request_metadata).to eq(item)
    end
  end

  describe '#update_instance_metadata' do
    it "sets the new metadata on the instance" do
      metadata = double("metadata")
      metadata_items = double("metadata_items")
      api = double("api")

      allow(tester).to receive(:log_debug)
      expect(tester).to receive(:api).and_return(api)
      expect(tester).to receive(:instance_metadata).at_least(:once).and_return(metadata)
      expect(tester).to receive(:password_request_metadata).and_return("password_request")
      expect(metadata).to receive(:items).at_least(:once).and_return(metadata_items)
      allow(metadata).to receive(:items=)
      expect(metadata_items).to receive(:<<).with("password_request")
      allow(metadata_items).to receive(:select)
      expect(api).to receive(:set_instance_metadata).with(project, zone, instance_name, metadata).and_return("operation123")
      expect(tester).to receive(:wait_for_operation).with("operation123")

      tester.update_instance_metadata
    end
  end

  describe '#private_key' do
    it "returns a 2048-bit private key" do
      expect(OpenSSL::PKey::RSA).to receive(:new).with(2048).and_return("test_key")
      expect(tester.private_key).to eq("test_key")
    end
  end

  describe '#public_key' do
    it "returns the public key" do
      private_key = double("private_key")
      expect(tester).to receive(:private_key).and_return(private_key)
      expect(private_key).to receive(:public_key).and_return("test_key")
      expect(tester.public_key).to eq("test_key")
    end
  end

  describe '#modulus' do
    it "returns a base64-encoded string" do
      public_key = double("public_key")
      key_der = double("public_key")
      expect(tester).to receive(:public_key).and_return(public_key)
      expect(public_key).to receive(:to_der).and_return(key_der)
      expect(key_der).to receive(:[]).with(33, 256).and_return("modulus")
      expect(Base64).to receive(:strict_encode64).with("modulus").and_return("base64_modulus")

      expect(tester.modulus).to eq("base64_modulus")
    end
  end

  describe '#exponent' do
    it "returns a base64-encoded string" do
      public_key = double("public_key")
      key_der = double("public_key")
      expect(tester).to receive(:public_key).and_return(public_key)
      expect(public_key).to receive(:to_der).and_return(key_der)
      expect(key_der).to receive(:[]).with(291, 3).and_return("exponent")
      expect(Base64).to receive(:strict_encode64).with("exponent").and_return("base64_exponent")

      expect(tester.exponent).to eq("base64_exponent")
    end
  end

  describe '#password_from_instance' do
    before do
      expect(tester).to receive(:response_from_console_port).and_return(response)
    end

    context "when the password reset fails" do
      let(:response) { { "passwordFound" => false } }

      it "raises an exception" do
        expect { tester.password_from_instance }.to raise_error(RuntimeError)
      end
    end

    context "when the password reset succeeds" do
      let(:response) { { "passwordFound" => true, "encryptedPassword" => "encpass" } }

      it "decrypts the password and returns it to the caller" do
        private_key = double("private_key")
        expect(tester).to receive(:private_key).and_return(private_key)
        expect(Base64).to receive(:strict_decode64).with("encpass").and_return("decoded_pass")
        expect(private_key).to receive(:private_decrypt).with("decoded_pass", OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING).and_return("decrypted_pass")
        expect(tester.password_from_instance).to eq("decrypted_pass")
      end
    end
  end

  describe '#response_from_console_port' do
    let(:api)                  { double("api") }
    let(:output_with_match)    { double("output", contents: contents_with_match) }
    let(:output_without_match) { double("output", contents: contents_without_match) }
    let(:match_event)          { { "modulus" => "test_modulus", "exponent" => "test_exponent" } }

    let(:contents_with_match) do
      <<-EOM
{"key1": "value1"}
{"modulus": "test_modulus", "exponent": "test_exponent"}
{"key2": "value2"}
EOM
    end

    let(:contents_without_match) do
      <<-EOM
{"key1": "value1"}
{"key2": "value2"}
EOM
    end

    before do
      allow(tester).to receive(:log_debug)
      allow(tester).to receive(:sleep)
      allow(tester).to receive(:modulus).and_return("test_modulus")
      allow(tester).to receive(:exponent).and_return("test_exponent")
      allow(tester).to receive(:api).and_return(api)
    end

    it "raises an exception if a timeout occurs" do
      expect(Timeout).to receive(:timeout).and_raise(Timeout::Error)
      expect { tester.response_from_console_port }.to raise_error(Timeout::Error)
    end

    context "when the console returns the response on the first try" do
      it "calls the API once and returns the event" do
        expect(api).to receive(:get_instance_serial_port_output).with(project, zone, instance_name, port: 4).once.and_return(output_with_match)
        expect(tester).not_to receive(:sleep)
        expect(tester.response_from_console_port).to eq(match_event)
      end
    end

    context "when the console returns the response on the third try" do
      it "calls the API three times and returns the event" do
        expect(api).to receive(:get_instance_serial_port_output).with(project, zone, instance_name, port: 4).exactly(3).times.and_return(output_without_match, output_without_match, output_with_match)
        expect(tester).to receive(:sleep).twice
        expect(tester.response_from_console_port).to eq(match_event)
      end
    end
  end

  describe '#wait_for_operation' do
    let(:operation_obj)     { double("operation_obj", name: "operation123") }
    let(:done_operation)    { double("done_operation", status: "DONE") }
    let(:in_prog_operation) { double("in_prog_operation", status: "RUNNING") }

    before do
      allow(tester).to receive(:log_debug)
      allow(tester).to receive(:sleep)
      allow(tester).to receive(:check_operation_for_errors!)
      allow(tester).to receive(:operation).with("operation123").and_return(done_operation)
    end

    it "raises an exception if a timeout occurs" do
      expect(Timeout).to receive(:timeout).and_raise(Timeout::Error)
      expect { tester.wait_for_operation(operation_obj) }.to raise_error(Timeout::Error)
    end

    context "when the operation is done on the first try" do
      it "only fetches the operation once" do
        expect(tester).to receive(:operation).with("operation123").once.and_return(done_operation)
        expect(tester).not_to receive(:sleep)
        tester.wait_for_operation(operation_obj)
      end
    end

    context "when the operation is done on the third try" do
      it "fetches the operation three times" do
        expect(tester).to receive(:operation).with("operation123").exactly(3).times.and_return(in_prog_operation, in_prog_operation, done_operation)
        expect(tester).to receive(:sleep).twice
        tester.wait_for_operation(operation_obj)
      end
    end
  end

  describe '#check_operation_for_errors!' do
    let(:operation) { double("operation") }

    before do
      expect(tester).to receive(:operation).and_return(operation)
    end

    context "when the operation has errors" do
      it "raises an exception with the errors" do
        error1 = double("error1", code: "ERROR1", message: "error 1")
        error2 = double("error2", code: "ERROR2", message: "error 2")
        error_obj = double("error_obj", errors: [ error1, error2 ])

        expect(operation).to receive(:error).twice.and_return(error_obj)
        expect { tester.check_operation_for_errors!("test_operation") }.to raise_error(RuntimeError, "Operation failed: ERROR1: error 1, ERROR2: error 2")
      end
    end

    context "when the operation has no errors" do
      it "does not raise an exception" do
        expect(operation).to receive(:error).and_return(nil)
        expect { tester.check_operation_for_errors!("test_operation") }.not_to raise_error
      end
    end
  end

  describe '#operation' do
    it "returns an operation from the API" do
      api = double("api")
      expect(tester).to receive(:api).and_return(api)
      expect(api).to receive(:get_zone_operation).with(project, zone, "operation123").and_return("test_operation")
      expect(tester.operation("operation123")).to eq("test_operation")
    end
  end

  describe '#log_debug' do
    it "writes the message to stderr if debug is enabled" do
      expect(tester).to receive(:debug).and_return(true)
      expect($stderr).to receive(:puts).with("test message")
      tester.log_debug("test message")
    end

    it "does not write the message to stderr if debug is disabled" do
      expect(tester).to receive(:debug).and_return(false)
      expect($stderr).not_to receive(:puts).with("test message")
      tester.log_debug("test message")
    end
  end
end
