import os
import platform
import subprocess
import sys
import ctypes
import winreg
import socket
import datetime
from typing import Tuple, Optional

class SecurityAnalyzer:
    """
    Простой анализатор безопасности для базовой проверки системы Windows.
    Проверяет соответствие базовым требованиям безопасности.
    """
    
    def __init__(self):
        """Инициализация анализатора безопасности."""
        self.system_info = {}
        self.issues = []
        self.recommendations = []
        self.is_admin = False
        self.encoding = 'cp866'  # Кодировка для русской Windows
        
    def get_windows_version(self) -> str:
        """Получение точной версии Windows."""
        try:
            # Используем реестр для получения точной версии
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                                    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
                product_name, _ = winreg.QueryValueEx(key, "ProductName")
                display_version, _ = winreg.QueryValueEx(key, "DisplayVersion")
                release_id, _ = winreg.QueryValueEx(key, "ReleaseId")
                current_build, _ = winreg.QueryValueEx(key, "CurrentBuild")
                winreg.CloseKey(key)
                
                if display_version:
                    return f"{product_name} (Сборка {current_build}, Версия {display_version})"
                elif release_id:
                    return f"{product_name} (Сборка {current_build}, Release ID: {release_id})"
                else:
                    return f"{product_name} (Сборка {current_build})"
                    
            except:
                # Альтернативный способ через команду
                result = subprocess.run(
                    'powershell -Command "(Get-WmiObject -Class Win32_OperatingSystem).Caption"',
                    capture_output=True,
                    text=True,
                    shell=True,
                    encoding=self.encoding
                )
                if result.returncode == 0 and result.stdout.strip():
                    return result.stdout.strip()
                else:
                    return f"Windows {platform.release()}"
                    
        except Exception as e:
            return f"Windows (не удалось определить версию: {str(e)})"
    
    def check_admin_rights_correct(self) -> bool:
        """Корректная проверка прав администратора для Windows."""
        try:
            # Способ 1: Проверка через ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            
            if is_admin:
                return True
                
            # Способ 2: Проверка через whoami
            result = subprocess.run(
                'whoami /groups | findstr /i "S-1-16-12288"',
                capture_output=True,
                text=True,
                shell=True,
                encoding=self.encoding
            )
            
            if result.returncode == 0 and result.stdout.strip():
                return True
                
            # Способ 3: Проверка через net session
            result = subprocess.run(
                'net session >nul 2>&1',
                shell=True
            )
            
            return result.returncode == 0
            
        except Exception:
            return False
    
    def run_command(self, command: str) -> Tuple[bool, str, str]:
        """
        Безопасное выполнение команды.
        
        Args:
            command: Команда для выполнения
            
        Returns:
            Кортеж (успех, stdout, stderr)
        """
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                encoding=self.encoding,
                timeout=15,
                errors='ignore'
            )
            return result.returncode == 0, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return False, "", "Таймаут выполнения"
        except Exception as e:
            return False, "", str(e)
    
    def get_system_info(self):
        """Получение информации о системе."""
        try:
            windows_version = self.get_windows_version()
            self.is_admin = self.check_admin_rights_correct()
            
            self.system_info = {
                'system': "Windows",
                'version': windows_version,
                'hostname': socket.gethostname(),
                'username': os.getenv('USERNAME', 'Неизвестно'),
                'is_admin': self.is_admin,
                'architecture': platform.architecture()[0],
                'processor': platform.processor(),
                'python_version': platform.python_version()
            }
            
            print("="*60)
            print("ИНФОРМАЦИЯ О СИСТЕМЕ")
            print("="*60)
            print(f"Операционная система: {self.system_info['version']}")
            print(f"Архитектура: {self.system_info['architecture']}")
            print(f"Имя компьютера: {self.system_info['hostname']}")
            print(f"Пользователь: {self.system_info['username']}")
            print(f"Права администратора: {'ДА' if self.is_admin else 'НЕТ'}")
            print(f"Процессор: {self.system_info['processor'][:50]}...")
            print(f"Версия Python: {self.system_info['python_version']}")
            print("="*60)
            
            # Проверяем права администратора для рекомендаций
            if not self.is_admin:
                self.issues.append("Программа запущена без прав администратора")
                self.recommendations.append("Перезапустите программу от имени администратора для полного доступа")
            
            return True
            
        except Exception as e:
            print(f"Ошибка при получении информации о системе: {str(e)}")
            return False
    
    def check_windows_firewall(self):
        """Проверка статуса брандмауэра Windows."""
        print("\n[ПРОВЕРКА БРАНДМАУЭРА WINDOWS]")
        print("-" * 40)
        
        try:
            # Проверка через PowerShell
            command = 'powershell -Command "Get-NetFirewallProfile | Select-Object Name, Enabled"'
            success, output, error = self.run_command(command)
            
            if success and output:
                print("Статус профилей брандмауэра:")
                print(output)
                
                # Анализируем статус
                profiles = {}
                lines = output.strip().split('\n')
                for line in lines:
                    if ':' in line:
                        parts = line.split(':')
                        if len(parts) >= 2:
                            key = parts[0].strip()
                            value = parts[1].strip()
                            profiles[key] = value
                
                # Проверяем каждый профиль
                disabled_profiles = []
                for profile, status in profiles.items():
                    if 'Enabled' in profile and status.upper() == 'FALSE':
                        profile_name = profile.replace('Enabled', '').strip()
                        disabled_profiles.append(profile_name)
                
                if disabled_profiles:
                    self.issues.append(f"Отключенные профили брандмауэра: {', '.join(disabled_profiles)}")
                    self.recommendations.append("Включите все профили брандмауэра Windows")
                else:
                    print(" Все профили брандмауэра включены")
                    
            else:
                # Альтернативный метод через netsh
                print("Используем альтернативный метод проверки...")
                command = 'netsh advfirewall show allprofiles'
                success, output, error = self.run_command(command)
                
                if success and output:
                    print(output)
                    
                    # Проверяем статус
                    if "Состояние                                   ВКЛЮЧЕНО" in output:
                        print(" Брандмауэр включен")
                    elif "Состояние                                   ВЫКЛЮЧЕНО" in output:
                        self.issues.append("Брандмауэр Windows выключен")
                        self.recommendations.append("Включите брандмауэр командой: netsh advfirewall set allprofiles state on")
                    else:
                        print(" Не удалось определить статус брандмауэра")
                else:
                    print(" Не удалось проверить статус брандмауэра")
            
        except Exception as e:
            print(f"Ошибка при проверке брандмауэра: {str(e)}")
    
    def check_windows_updates(self):
        """Проверка обновлений Windows."""
        print("\n[ПРОВЕРКА ОБНОВЛЕНИЙ WINDOWS]")
        print("-" * 40)
        
        try:
            if not self.is_admin:
                print(" Для проверки обновлений требуются права администратора")
                return
            
            # Проверка последних установленных обновлений
            command = 'powershell -Command "Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 3 | Format-Table -AutoSize"'
            success, output, error = self.run_command(command)
            
            if success and output:
                print("Последние установленные обновления:")
                print(output)
                
                # Проверка времени последнего обновления
                command = 'powershell -Command "(Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1).InstalledOn"'
                success, date_output, _ = self.run_command(command)
                
                if success and date_output.strip():
                    last_update = date_output.strip()
                    print(f"Дата последнего обновления: {last_update}")
                    
                    # Проверяем, не слишком ли старое обновление
                    try:
                        # Парсим дату из строки (формат может быть разным)
                        if '/' in last_update:
                            update_date = datetime.datetime.strptime(last_update.split()[0], "%m/%d/%Y")
                        elif '-' in last_update:
                            update_date = datetime.datetime.strptime(last_update.split()[0], "%Y-%m-%d")
                        else:
                            update_date = datetime.datetime.now()
                            
                        days_since_update = (datetime.datetime.now() - update_date).days
                        
                        if days_since_update > 30:
                            self.recommendations.append(f"Последнее обновление было {days_since_update} дней назад. Проверьте наличие новых обновлений")
                    except:
                        pass
            else:
                print("Не удалось получить информацию об обновлениях")
                self.recommendations.append("Проверьте наличие обновлений вручную через 'Параметры Windows > Обновление и безопасность'")
                
        except Exception as e:
            print(f"Ошибка при проверке обновлений: {str(e)}")
    
    def check_antivirus_status(self):
        """Проверка статуса антивирусной защиты."""
        print("\n[ПРОВЕРКА АНТИВИРУСНОЙ ЗАЩИТЫ]")
        print("-" * 40)
        
        try:
            # Проверка через SecurityCenter
            command = 'powershell -Command "Get-Service WinDefend, Sense, wscsvc | Select-Object Name, Status, DisplayName"'
            success, output, error = self.run_command(command)
            
            if success and output:
                print("Статус служб безопасности:")
                print(output)
                
                # Проверяем Защитник Windows
                if "WinDefend" in output and "Running" in output:
                    print(" Защитник Windows активен")
                else:
                    self.issues.append("Защитник Windows не запущен")
                    self.recommendations.append("Запустите службу Защитника Windows или установите антивирус")
            
            # Проверка наличия стороннего антивируса
            command = 'powershell -Command "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct"'
            success, output, error = self.run_command(command)
            
            if success and output:
                print("\nУстановленные антивирусные продукты:")
                print(output)
            elif not "WinDefend" in locals():
                self.recommendations.append("Рассмотрите возможность установки антивирусного ПО")
                
        except Exception as e:
            print(f"Ошибка при проверке антивируса: {str(e)}")
    
    def check_network_security(self):
        """Проверка сетевой безопасности."""
        print("\n[ПРОВЕРКА СЕТЕВОЙ БЕЗОПАСНОСТИ]")
        print("-" * 40)
        
        try:
            # Проверка активных подключений
            print("Активные сетевые подключения:")
            command = 'netstat -an | findstr :'
            success, output, error = self.run_command(command)
            
            if success and output:
                lines = output.strip().split('\n')
                established = [l for l in lines if 'ESTABLISHED' in l]
                listening = [l for l in lines if 'LISTENING' in l]
                
                print(f"Всего подключений: {len(lines)}")
                print(f"Установленных: {len(established)}")
                print(f"Ожидающих: {len(listening)}")
                
                # Показываем подозрительные порты
                suspicious_ports = [21, 22, 23, 25, 135, 139, 445, 3389]
                suspicious = []
                
                for line in listening:
                    for port in suspicious_ports:
                        if f":{port}" in line:
                            suspicious.append(f"Порт {port} открыт: {line[:80]}")
                            break
                
                if suspicious:
                    print("\n Обнаружены открытые порты:")
                    for warn in suspicious[:3]:
                        print(f"  • {warn}")
                    if len(suspicious) > 3:
                        print(f"  • ... и еще {len(suspicious)-3} предупреждений")
            else:
                print("Не удалось получить информацию о сетевых подключениях")
                
        except Exception as e:
            print(f"Ошибка при проверке сети: {str(e)}")
    
    def check_user_accounts(self):
        """Проверка учетных записей пользователей."""
        print("\n[ПРОВЕРКА УЧЕТНЫХ ЗАПИСЕЙ]")
        print("-" * 40)
        
        try:
            if not self.is_admin:
                print(" Для проверки учетных записей требуются права администратора")
                return
            
            # Получаем список пользователей
            command = 'net user'
            success, output, error = self.run_command(command)
            
            if success and output:
                print("Учетные записи на компьютере:")
                lines = output.strip().split('\n')
                for line in lines[:10]:  # Показываем первые 10 записей
                    if line.strip():
                        print(f"  {line}")
                
                # Проверяем наличие учетной записи Администратора
                if "Администратор" in output or "Administrator" in output:
                    command = 'net user Администратор'
                    success, admin_info, _ = self.run_command(command)
                    if success and "Аккаунт активен Да" in admin_info:
                        self.recommendations.append("Учетная запись Администратор активна. Рассмотрите возможность ее отключения")
            
        except Exception as e:
            print(f"Ошибка при проверке учетных записей: {str(e)}")
    
    def check_shared_resources(self):
        """Проверка общих ресурсов."""
        print("\n[ПРОВЕРКА ОБЩИХ РЕСУРСОВ]")
        print("-" * 40)
        
        try:
            # Проверка общих папок
            command = 'net share'
            success, output, error = self.run_command(command)
            
            if success and output:
                shares = [line for line in output.split('\n') if line.strip() and 'Имя' not in line and '---' not in line]
                
                if shares:
                    print("Общие ресурсы:")
                    for share in shares[:5]:  # Показываем первые 5
                        print(f"  • {share}")
                    
                    if len(shares) > 5:
                        print(f"  • ... и еще {len(shares)-5} ресурсов")
                    
                    self.recommendations.append("Проверьте необходимость всех общих ресурсов. Отключите ненужные")
                else:
                    print(" Общие ресурсы не найдены")
            else:
                print("Не удалось проверить общие ресурсы")
                
        except Exception as e:
            print(f"Ошибка при проверке общих ресурсов: {str(e)}")
    
    def show_security_summary(self):
        """Показать итоговую сводку безопасности."""
        print("\n" + "="*60)
        print("ИТОГОВАЯ СВОДКА БЕЗОПАСНОСТИ")
        print("="*60)
        
        # Сводка по проверкам
        print(f"\nВыполнено проверок: 7")
        print(f"Обнаружено проблем: {len(self.issues)}")
        print(f"Дано рекомендаций: {len(self.recommendations)}")
        
        # Проблемы
        if self.issues:
            print(f"\n{'='*40}")
            print("ОБНАРУЖЕННЫЕ ПРОБЛЕМЫ:")
            print('-'*40)
            for i, issue in enumerate(self.issues, 1):
                print(f"{i}. {issue}")
        else:
            print(f"\n{'='*40}")
            print(" КРИТИЧЕСКИХ ПРОБЛЕМ НЕ ОБНАРУЖЕНО")
            print('='*40)
        
        # Рекомендации
        if self.recommendations:
            print(f"\n{'='*40}")
            print("РЕКОМЕНДАЦИИ ПО УЛУЧШЕНИЮ БЕЗОПАСНОСТИ:")
            print('-'*40)
            for i, rec in enumerate(self.recommendations, 1):
                print(f"{i}. {rec}")
        
        print("\n" + "="*60)
        print("Проверка завершена!")
        print("="*60)

def main():
    """Главная функция программы."""
    print("\n" + "="*60)
    print("АНАЛИЗАТОР БЕЗОПАСНОСТИ WINDOWS")
    print("="*60)
    
    analyzer = SecurityAnalyzer()
    
    # Получаем информацию о системе
    analyzer.get_system_info()
    
    # Выполняем проверки
    print("\n" + "="*60)
    print("ВЫПОЛНЕНИЕ ПРОВЕРОК БЕЗОПАСНОСТИ")
    print("="*60)
    
    # Список проверок
    checks = [
        analyzer.check_windows_firewall,
        analyzer.check_windows_updates,
        analyzer.check_antivirus_status,
        analyzer.check_network_security,
        analyzer.check_user_accounts,
        analyzer.check_shared_resources
    ]
    
    # Выполняем все проверки
    for check_func in checks:
        check_func()
    
    # Показываем сводку
    analyzer.show_security_summary()
    
    return analyzer

def show_menu():
    """Показать главное меню."""
    print("\n" + "="*60)
    print("ГЛАВНОЕ МЕНЮ - АНАЛИЗАТОР БЕЗОПАСНОСТИ")
    print("="*60)
    print("1. Запустить полную проверку безопасности")
    print("2. Проверить только брандмауэр")
    print("3. Проверить только сетевую безопасность")
    print("4. Проверить антивирусную защиту")
    print("5. Показать информацию о системе")
    print("6. Выход")
    
    try:
        choice = input("\nВыберите действие (1-6): ").strip()
        return choice
    except (KeyboardInterrupt, EOFError):
        return '6'

if __name__ == "__main__":
    # Устанавливаем корректную кодировку для Windows
    if sys.platform == "win32":
        os.system("chcp 65001 >nul 2>&1")
    
    analyzer_instance = None
    
    while True:
        try:
            choice = show_menu()
            
            if choice == '1':
                analyzer_instance = main()
                if analyzer_instance:
                    input("\nНажмите Enter для возврата в меню...")
                    
            elif choice == '2':
                analyzer_instance = SecurityAnalyzer()
                analyzer_instance.get_system_info()
                analyzer_instance.check_windows_firewall()
                input("\nНажмите Enter для возврата в меню...")
                
            elif choice == '3':
                analyzer_instance = SecurityAnalyzer()
                analyzer_instance.get_system_info()
                analyzer_instance.check_network_security()
                input("\nНажмите Enter для возврата в меню...")
                
            elif choice == '4':
                analyzer_instance = SecurityAnalyzer()
                analyzer_instance.get_system_info()
                analyzer_instance.check_antivirus_status()
                input("\nНажмите Enter для возврата в меню...")
                
            elif choice == '5':
                analyzer_instance = SecurityAnalyzer()
                analyzer_instance.get_system_info()
                input("\nНажмите Enter для возврата в меню...")
                
            elif choice == '6':
                print("\n" + "="*60)
                print("Выход из программы...")
                print("="*60)
                break
                
            else:
                print("\n Неверный выбор. Попробуйте снова.")
                
        except KeyboardInterrupt:
            print("\n\nПрограмма прервана пользователем")
            break
        except Exception as e:
            print(f"\n Ошибка: {str(e)}")
            print("Попробуйте снова.")
            continue
