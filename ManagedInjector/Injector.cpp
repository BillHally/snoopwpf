// (c) Copyright Cory Plotts.
// This source is subject to the Microsoft Public License (Ms-PL).
// Please see http://go.microsoft.com/fwlink/?LinkID=131993 for details.
// All other rights reserved.

#include "stdafx.h"

#include "Injector.h"
#include <vcclr.h>

using namespace ManagedInjector;

System::Reflection::Assembly ^ OnAssemblyResolve(System::Object ^sender, System::ResolveEventArgs ^args);
static unsigned int WM_GOBABYGO = ::RegisterWindowMessage(L"Injector_GOBABYGO!");
static HHOOK _messageHookHandle;

//-----------------------------------------------------------------------------
//Spying Process functions follow
//-----------------------------------------------------------------------------
void Injector::Launch(System::IntPtr windowHandle, System::String^ assembly, System::String^ className, System::String^ methodName)
{
	System::String^ assemblyClassAndMethod = assembly + "$" + className + "$" + methodName;
	pin_ptr<const wchar_t> acmLocal = PtrToStringChars(assemblyClassAndMethod);

	HINSTANCE hinstDLL;	

	if (::GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCTSTR)&MessageHookProc, &hinstDLL))
	{
		LogMessage("GetModuleHandleEx successful", true);
		DWORD processID = 0;
		DWORD threadID = ::GetWindowThreadProcessId((HWND)windowHandle.ToPointer(), &processID);

		if (processID)
		{
			LogMessage("Got process id", true);
			HANDLE hProcess = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
			if (hProcess)
			{
				LogMessage("Got process handle", true);
				int buffLen = (assemblyClassAndMethod->Length + 1) * sizeof(wchar_t);
				void* acmRemote = ::VirtualAllocEx(hProcess, NULL, buffLen, MEM_COMMIT, PAGE_READWRITE);

				if (acmRemote)
				{
					LogMessage("VirtualAllocEx successful", true);
					::WriteProcessMemory(hProcess, acmRemote, acmLocal, buffLen, NULL);
				
					_messageHookHandle = ::SetWindowsHookEx(WH_CALLWNDPROC, &MessageHookProc, hinstDLL, threadID);

					if (_messageHookHandle)
					{
						LogMessage("SetWindowsHookEx successful", true);
						::SendMessage((HWND)windowHandle.ToPointer(), WM_GOBABYGO, (WPARAM)acmRemote, 0);
						::UnhookWindowsHookEx(_messageHookHandle);
					}

					::VirtualFreeEx(hProcess, acmRemote, 0, MEM_RELEASE);
				}

				::CloseHandle(hProcess);
			}
		}
		::FreeLibrary(hinstDLL);
	}
}

void Injector::LogMessage(System::String^ message, bool append)
{	            
	System::String ^ applicationDataPath = Environment::GetFolderPath(Environment::SpecialFolder::ApplicationData);
	applicationDataPath += "\\Snoop";

	if (!System::IO::Directory::Exists(applicationDataPath))
	{
		System::IO::Directory::CreateDirectory(applicationDataPath);
	}

	System::String ^ pathname = applicationDataPath + "\\SnoopLog.txt";

	if (!append)    
	{    
		System::IO::File::Delete(pathname);        
	}

	System::IO::FileInfo ^ fi = gcnew System::IO::FileInfo(pathname);
	            
	System::IO::StreamWriter ^ sw = fi->AppendText();   
	sw->WriteLine(System::DateTime::Now.ToString("MM/dd/yyyy HH:mm:ss") + " : " + message);
	sw->Close();
}

value struct AssemblyBindingRedirect
{
    System::String^ Name;
    System::String^ MinVersion;
    System::String^ MaxVersion;
    System::String^ NewVersion;

};

System::Collections::Generic::List<AssemblyBindingRedirect>^ GetAssemblyBindingRedirects(System::String^ assemblyPath)
{
    auto configFilePath = System::String::Format("{0}.config", assemblyPath);
    auto xml = gcnew System::Xml::XmlDocument();
    xml->Load(configFilePath);
    auto assemblyNodes = xml->GetElementsByTagName("dependentAssembly");

    System::Collections::Generic::List<AssemblyBindingRedirect>^ bindingRedirects = gcnew System::Collections::Generic::List<AssemblyBindingRedirect>();

    for each (System::Xml::XmlElement^ assemblyNode in assemblyNodes)
    {
        auto assemblyName = assemblyNode->GetElementsByTagName("assemblyIdentity")->Item(0)->Attributes->GetNamedItem("name")->Value;
        auto bindingRedirectAttributes = assemblyNode->GetElementsByTagName("bindingRedirect")->Item(0)->Attributes;
        
        auto oldVersion = bindingRedirectAttributes->GetNamedItem("oldVersion")->Value;
        auto minAndMax = oldVersion->Split('-');
        auto minVersion = minAndMax[0];
        auto maxVersion = minAndMax[1];
        auto newVersion = bindingRedirectAttributes->GetNamedItem("newVersion")->Value;

        auto redirect = AssemblyBindingRedirect();
        redirect.Name = assemblyName;
        redirect.MinVersion = minVersion;
        redirect.MaxVersion = maxVersion;
        redirect.NewVersion = newVersion;

        bindingRedirects->Add(redirect);
    }

    return bindingRedirects;
}

ref class AssemblyBindingRedirector
{
private:
    System::Collections::Generic::List<AssemblyBindingRedirect>^ bindingRedirects = nullptr;
    System::String^ assemblyPath = nullptr;

public:
    AssemblyBindingRedirector(System::String^ assemblyPath)
    {
        bindingRedirects = GetAssemblyBindingRedirects(assemblyPath);
        this->assemblyPath = assemblyPath;

        // TODO: Move this?
        System::AppDomain::CurrentDomain->AssemblyResolve += gcnew System::ResolveEventHandler(this, &AssemblyBindingRedirector::OnAssemblyResolve);
    }

    System::Reflection::Assembly^ OnAssemblyResolve(System::Object ^sender, System::ResolveEventArgs ^args)
    {
        for each (auto bindingRedirect in bindingRedirects)
        {
            if (bindingRedirect.Name->Equals(args->Name))
            {
                auto loadedFromAssemblyFolder = System::Reflection::Assembly::LoadFrom(System::IO::Path::GetDirectoryName(assemblyPath));

                if (loadedFromAssemblyFolder != nullptr)
                {
                    return loadedFromAssemblyFolder;
                }

                auto loadedFromGac = System::Reflection::Assembly::LoadWithPartialName(args->Name);

                if (loadedFromGac != nullptr)
                {
                    return loadedFromGac;
                }

                return nullptr;
            }
        }

        return nullptr;
    }
};

__declspec(dllexport) 
LRESULT __stdcall MessageHookProc(int nCode, WPARAM wparam, LPARAM lparam)
{
	if (nCode == HC_ACTION)
	{
		CWPSTRUCT* msg = (CWPSTRUCT*)lparam;
		if (msg != NULL && msg->message == WM_GOBABYGO)
		{
			System::Diagnostics::Debug::WriteLine("Got WM_GOBABYGO message");
            System::Diagnostics::Debugger::Break();
			wchar_t* acmRemote = (wchar_t*)msg->wParam;

			String^ acmLocal = gcnew System::String(acmRemote);
			System::Diagnostics::Debug::WriteLine(System::String::Format("acmLocal = {0}", acmLocal));
			cli::array<System::String^>^ acmSplit = acmLocal->Split('$');

            auto assemblyPath = acmSplit[0];
            auto typeName     = acmSplit[1];
            auto methodName   = acmSplit[2];
            
            System::Diagnostics::Debug::WriteLine(String::Format("About to load assembly {0}", assemblyPath));
			System::Reflection::Assembly^ assembly = System::Reflection::Assembly::LoadFrom(assemblyPath);
			if (assembly != nullptr)
			{
				System::Diagnostics::Debug::WriteLine(String::Format("About to load type {0}", typeName));
				System::Type^ type = assembly->GetType(typeName);
				if (type != nullptr)
				{
					System::Diagnostics::Debug::WriteLine(String::Format("Just loaded the type {0}", typeName));
					System::Reflection::MethodInfo^ methodInfo = type->GetMethod(methodName, System::Reflection::BindingFlags::Static | System::Reflection::BindingFlags::Public);
					if (methodInfo != nullptr)
					{
						System::Diagnostics::Debug::WriteLine(System::String::Format("About to invoke {0} on type {1}", methodInfo->Name, typeName));

                        // If we've got this far we're almost ready to invoke the method - but if the assembly (whether dll or exe) we're injecting has
                        // binding redirects in its .config, they won't apply here (since this function runs inside the target process), so we'll need to
                        // load it ourselves, and perform any redirection that's required ourselves
                        auto _ = gcnew AssemblyBindingRedirector(assemblyPath);

						Object ^ returnValue = methodInfo->Invoke(nullptr, nullptr);
						if (nullptr == returnValue)
							returnValue = "NULL";
						System::Diagnostics::Debug::WriteLine(String::Format("Return value of {0} on type {1} is {2}", methodInfo->Name, typeName, returnValue));
					}
				}
			}
		}
	}

    return CallNextHookEx(_messageHookHandle, nCode, wparam, lparam);
}
