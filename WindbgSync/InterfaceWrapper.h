#pragma once

namespace srcsync
{
	template <typename InterfacePointerType>
	class InterfaceWrapper
	{
	public:
		InterfaceWrapper() = default;

		InterfaceWrapper(InterfacePointerType Interface) : m_Interface(Interface)
		{
		}

		~InterfaceWrapper()
		{
			if (m_Interface)
			{
				m_Interface->Release();
			}
		}

		InterfacePointerType operator->()
		{
			return m_Interface;
		}

		operator bool() const
		{
			return m_Interface;
		}
	private:
		InterfacePointerType m_Interface;
	};
}