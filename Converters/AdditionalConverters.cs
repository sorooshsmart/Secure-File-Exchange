using System;
using System.Globalization;
using System.Windows;
using System.Windows.Data;
using SecureFileExchange.ViewModels;

namespace SecureFileExchange.Converters
{
    public class RecipientTypeConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is RecipientType recipientType && parameter is string paramStr)
            {
                if (paramStr == "Internal")
                {
                    if (targetType == typeof(bool))
                        return recipientType == RecipientType.Internal;
                    else if (targetType == typeof(Visibility))
                        return recipientType == RecipientType.Internal ? Visibility.Visible : Visibility.Collapsed;
                }
                else if (paramStr == "External")
                {
                    if (targetType == typeof(bool))
                        return recipientType == RecipientType.External;
                    else if (targetType == typeof(Visibility))
                        return recipientType == RecipientType.External ? Visibility.Visible : Visibility.Collapsed;
                }
            }

            return targetType == typeof(bool) ? false : Visibility.Collapsed;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is bool boolValue && boolValue && parameter is string paramStr)
            {
                if (paramStr == "Internal")
                    return RecipientType.Internal;
                else if (paramStr == "External")
                    return RecipientType.External;
            }

            return RecipientType.Internal;
        }
    }

    public class SenderTypeConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is SenderType senderType && parameter is string paramStr)
            {
                if (paramStr == "Internal")
                {
                    if (targetType == typeof(bool))
                        return senderType == SenderType.Internal;
                    else if (targetType == typeof(Visibility))
                        return senderType == SenderType.Internal ? Visibility.Visible : Visibility.Collapsed;
                }
                else if (paramStr == "External")
                {
                    if (targetType == typeof(bool))
                        return senderType == SenderType.External;
                    else if (targetType == typeof(Visibility))
                        return senderType == SenderType.External ? Visibility.Visible : Visibility.Collapsed;
                }
            }

            return targetType == typeof(bool) ? false : Visibility.Collapsed;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is bool boolValue && boolValue && parameter is string paramStr)
            {
                if (paramStr == "Internal")
                    return SenderType.Internal;
                else if (paramStr == "External")
                    return SenderType.External;
            }

            return SenderType.Internal;
        }
    }

    public class StringToVisibilityConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is string str && !string.IsNullOrWhiteSpace(str))
                return Visibility.Visible;

            return Visibility.Collapsed;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
}