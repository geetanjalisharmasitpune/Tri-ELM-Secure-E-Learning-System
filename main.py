import pandas as pd
import numpy as np
import os
from datetime import datetime
from collections import defaultdict
import json
import warnings
from sklearn.preprocessing import StandardScaler
warnings.filterwarnings('ignore')

class ELearningSecurityPreprocessor:
    """
    Preprocessing stage for e-learning security system
    """
    
    def __init__(self, base_path):
        self.base_path = base_path
        self.data_snapshots = {}
        self.tokenized_memory = {}
        self.cleaned_data = {}
        self.sensitivity_classified = {}
        self.api_sequences = {}
        self.memory_snapshots = {}
        
        # Define sensitivity levels based on folder names
        self.sensitivity_levels = {
            'high': ['exam_responses', 'instructor_feedback', 'authentication_logs', 
                    'authorization_logs', 'security_events', 'token_events'],
            'medium': ['scores', 'attendance_logs', 'peer_interactions', 'assignment_submissions',
                      'learning_progress', 'threat_detection'],
            'low': ['system_metadata', 'student_profiles', 'courses', 'connection_logs',
                   'traffic_statistics', 'performance_logs']
        }
        
        # Define which files to look for (without .csv extension)
        self.file_patterns = [
            'api_anomalies', 'api_rate_limits', 'api_requests', 'api_responses',
            'assignment_submissions', 'attack_events', 'attendance_logs',
            'authentication_logs', 'authorization_logs', 'autosave_states',
            'connection_logs', 'courses', 'delayed_uploads', 'device_events',
            'discussion_logs', 'encryption_events', 'exam_responses',
            'instructor_feedback', 'interservice_communication', 'key_rotation_logs',
            'learning_progress', 'network_events', 'peer_interactions',
            'performance_logs', 'scores', 'security_events', 'session_logs',
            'student_activity', 'student_profiles', 'system_metadata',
            'threat_detection', 'tls_events', 'token_events', 'traffic_statistics',
            'tri_elm_master_education', 'tri_elm_master_security'
        ]

    def load_all_data(self):
        """Load all CSV files from the directory"""
        print(f"Loading data from: {self.base_path}")
        print("="*60)
        
        # Get all CSV files in the directory
        csv_files = [f for f in os.listdir(self.base_path) if f.endswith('.csv')]
        
        if not csv_files:
            print(f"❌ ERROR: No CSV files found in {self.base_path}")
            print("   Please check the path and make sure CSV files exist.")
            return
        
        print(f"Found {len(csv_files)} CSV files\n")
        
        # Load each CSV file
        for csv_file in csv_files:
            file_path = os.path.join(self.base_path, csv_file)
            file_name = csv_file.replace('.csv', '')
            
            try:
                df = pd.read_csv(file_path)
                if not df.empty:
                    # Store by file name (without .csv)
                    self.data_snapshots[file_name] = df
                    print(f"✓ Loaded {file_name}: {len(df)} records")
                else:
                    print(f"⚠ Warning: {file_name} is empty")
            except Exception as e:
                print(f"✗ Error loading {csv_file}: {e}")
        
        print(f"\n✓ Total loaded datasets: {len(self.data_snapshots)}")

    def capture_memory_snapshots(self):
        """Capture transient memory states at predefined micro-intervals"""
        print("\n" + "="*60)
        print("CAPTURING MEMORY SNAPSHOTS")
        print("="*60)
        
        memory_folders = ['autosave_states', 'api_requests', 'api_responses', 
                         'delayed_uploads', 'exam_responses', 'student_activity']
        
        for folder in memory_folders:
            if folder in self.data_snapshots:
                df = self.data_snapshots[folder].copy()
                snapshots = []
                
                # Process each row as a snapshot
                for idx, row in df.iterrows():
                    snapshot = {
                        'source': folder,
                        'timestamp': row.get('timestamp', datetime.now()),
                        'data': row.to_dict()
                    }
                    snapshots.append(snapshot)
                
                self.memory_snapshots[folder] = snapshots
                print(f"✓ Captured {len(snapshots)} snapshots from {folder}")
            else:
                print(f"ℹ No data found for {folder}")

    def tokenize_memory(self):
        """Divide memory snapshots into structured tokens with semantic categories"""
        print("\n" + "="*60)
        print("TOKENIZING MEMORY SNAPSHOTS")
        print("="*60)
        
        category_keywords = {
            'metadata': ['id', 'timestamp', 'session', 'device', 'version', 'protocol', 'status'],
            'sensitive_academic': ['exam', 'score', 'grade', 'answer', 'response', 'feedback', 'submission'],
            'user_input': ['message', 'post', 'comment', 'resource_view', 'activity_type'],
            'system_generated': ['system_event', 'performance', 'traffic', 'connection', 'attack'],
            'authentication': ['token', 'auth', 'login', 'password', 'certificate']
        }
        
        for source, snapshots in self.memory_snapshots.items():
            tokenized_snapshots = []
            
            for snapshot in snapshots:
                tokens = []
                data = snapshot['data']
                
                for key, value in data.items():
                    category = self._determine_token_category(key, category_keywords)
                    token = {
                        'field': key,
                        'value': value,
                        'category': category,
                        'source': source,
                        'timestamp': snapshot['timestamp']
                    }
                    tokens.append(token)
                
                tokenized_snapshots.append(tokens)
            
            self.tokenized_memory[source] = tokenized_snapshots
            print(f"✓ Tokenized {len(tokenized_snapshots)} snapshots from {source}")

    def _determine_token_category(self, field_name, category_keywords):
        """Determine the semantic category of a field"""
        field_lower = field_name.lower()
        
        for category, keywords in category_keywords.items():
            for keyword in keywords:
                if keyword in field_lower:
                    return category
        
        return 'general'

    def clean_and_normalize_data(self):
        """Remove redundant, corrupted records and normalize numerical attributes"""
        print("\n" + "="*60)
        print("CLEANING AND NORMALIZING DATA")
        print("="*60)
        
        for folder_name, df in self.data_snapshots.items():
            df_clean = df.copy()
            initial_rows = len(df_clean)
            
            # Remove duplicate rows
            df_clean = df_clean.drop_duplicates()
            
            # Remove rows with all null values
            df_clean = df_clean.dropna(how='all')
            
            # Handle missing values
            for col in df_clean.columns:
                if df_clean[col].dtype in ['int64', 'float64']:
                    if df_clean[col].isnull().any():
                        df_clean[col] = df_clean[col].fillna(df_clean[col].median())
                elif df_clean[col].dtype == 'object':
                    if df_clean[col].isnull().any():
                        df_clean[col] = df_clean[col].fillna('unknown')
            
            # Normalize numerical attributes
            numerical_cols = df_clean.select_dtypes(include=['int64', 'float64']).columns
            if len(numerical_cols) > 0:
                scaler = StandardScaler()
                df_clean[numerical_cols] = scaler.fit_transform(df_clean[numerical_cols])
            
            self.cleaned_data[folder_name] = df_clean
            print(f"✓ Cleaned {folder_name}: {initial_rows} → {len(df_clean)} records")

    def classify_sensitivity(self):
        """Assign sensitivity levels to academic data fragments"""
        print("\n" + "="*60)
        print("CLASSIFYING DATA SENSITIVITY")
        print("="*60)
        
        for folder_name, df in self.cleaned_data.items():
            df_sensitive = df.copy()
            df_sensitive['sensitivity_level'] = 'low'
            
            # Classify based on folder name
            if folder_name in self.sensitivity_levels['high']:
                df_sensitive['sensitivity_level'] = 'high'
            elif folder_name in self.sensitivity_levels['medium']:
                df_sensitive['sensitivity_level'] = 'medium'
            
            # Further refine based on column values
            for col in df_sensitive.columns:
                if col in ['exam_score', 'assignment_score', 'total_score', 'risk_score', 'anomaly_score']:
                    if col in df_sensitive.columns and df_sensitive[col].dtype in ['int64', 'float64']:
                        # Use actual values from data
                        df_sensitive['sensitivity_level'] = df_sensitive[col].apply(
                            lambda x: 'high' if isinstance(x, (int, float)) and x > 70 else 
                                     'medium' if isinstance(x, (int, float)) and x > 40 else 'low'
                        )
            
            self.sensitivity_classified[folder_name] = df_sensitive
            
            # Print distribution
            dist = df_sensitive['sensitivity_level'].value_counts()
            dist_str = ', '.join([f"{k}: {v}" for k, v in dist.items()])
            print(f"✓ {folder_name}: {dist_str}")

    def preprocess_api_requests(self):
        """Extract API request information and construct interaction sequences"""
        print("\n" + "="*60)
        print("PREPROCESSING API REQUESTS")
        print("="*60)
        
        if 'api_requests' not in self.data_snapshots:
            print("ℹ No api_requests data found")
            return
        
        df_api = self.data_snapshots['api_requests'].copy()
        
        # Convert timestamp if exists
        if 'timestamp' in df_api.columns:
            try:
                df_api['timestamp'] = pd.to_datetime(df_api['timestamp'])
                if 'user_id' in df_api.columns:
                    df_api = df_api.sort_values(['user_id', 'timestamp'])
            except:
                pass
        
        api_features = []
        
        # Group by user_id if exists
        if 'user_id' in df_api.columns:
            for user_id, group in df_api.groupby('user_id'):
                user_sequences = []
                
                for idx, row in group.iterrows():
                    sequence_item = {
                        'user_id': user_id,
                        'request_id': row.get('request_id'),
                        'endpoint': row.get('endpoint'),
                        'method': row.get('http_method'),
                        'status': row.get('status_code'),
                        'latency': row.get('latency_ms'),
                        'timestamp': row.get('timestamp'),
                        'permission_level': row.get('authorization_status')
                    }
                    user_sequences.append(sequence_item)
                
                privilege_level = self._calculate_privilege_level(user_sequences)
                
                for item in user_sequences:
                    item['privilege_level'] = privilege_level
                
                api_features.extend(user_sequences)
        else:
            # No user_id column, process sequentially
            for idx, row in df_api.iterrows():
                sequence_item = {
                    'request_id': row.get('request_id'),
                    'endpoint': row.get('endpoint'),
                    'method': row.get('http_method'),
                    'status': row.get('status_code'),
                    'latency': row.get('latency_ms'),
                    'timestamp': row.get('timestamp'),
                    'permission_level': row.get('authorization_status', 'unknown')
                }
                api_features.append(sequence_item)
        
        self.api_sequences['api_requests'] = api_features
        print(f"✓ Processed {len(api_features)} API requests")

    def _calculate_privilege_level(self, sequences):
        """Calculate privilege level based on API access patterns"""
        high_priv_endpoints = ['/admin', '/grades/update', '/auth/reset', '/security']
        medium_priv_endpoints = ['/courses', '/assignments', '/attendance']
        
        high_count = sum(1 for s in sequences if any(endpoint in str(s.get('endpoint', '')) for endpoint in high_priv_endpoints))
        medium_count = sum(1 for s in sequences if any(endpoint in str(s.get('endpoint', '')) for endpoint in medium_priv_endpoints))
        
        if high_count > 0:
            return 'high'
        elif medium_count > 0:
            return 'medium'
        else:
            return 'low'

    def extract_features_memory(self):
        """Extract memory-behavior features"""
        print("\n" + "="*60)
        print("EXTRACTING MEMORY-BEHAVIOR FEATURES")
        print("="*60)
        
        memory_features = []
        
        for source, snapshots in self.tokenized_memory.items():
            for tokens in snapshots:
                features = {
                    'source': source,
                    'token_count': len(tokens),
                    'unique_tokens': len(set(str(t.get('field', '')) for t in tokens)),
                    'duplication_rate': self._calculate_duplication_rate(tokens),
                    'sensitive_token_ratio': self._calculate_sensitive_token_ratio(tokens),
                    'transition_patterns': self._calculate_transition_patterns(tokens),
                    'timestamp': tokens[0].get('timestamp', datetime.now()) if tokens else datetime.now()
                }
                
                # Calculate temporal delay between consecutive tokens
                if len(tokens) > 1:
                    features['temporal_delay'] = self._calculate_temporal_delay(tokens)
                else:
                    features['temporal_delay'] = 0
                
                memory_features.append(features)
        
        print(f"✓ Extracted memory features for {len(memory_features)} snapshots")
        return memory_features

    def _calculate_duplication_rate(self, tokens):
        """Calculate token duplication rate"""
        if not tokens:
            return 0
        token_values = [str(t.get('value', '')) for t in tokens]
        unique_values = set(token_values)
        return 1 - (len(unique_values) / len(token_values)) if len(token_values) > 0 else 0

    def _calculate_sensitive_token_ratio(self, tokens):
        """Calculate ratio of sensitive tokens"""
        if not tokens:
            return 0
        sensitive_categories = ['sensitive_academic', 'authentication']
        sensitive_count = sum(1 for t in tokens if t.get('category', '') in sensitive_categories)
        return sensitive_count / len(tokens) if len(tokens) > 0 else 0

    def _calculate_temporal_delay(self, tokens):
        """Calculate temporal delay between memory operations"""
        if len(tokens) < 2:
            return 0
        
        # Extract timestamps if available
        timestamps = []
        for t in tokens:
            ts = t.get('timestamp')
            if ts and hasattr(ts, 'timestamp'):
                timestamps.append(ts.timestamp())
            elif ts and isinstance(ts, (int, float)):
                timestamps.append(float(ts))
        
        if len(timestamps) < 2:
            return 0
        
        # Calculate average delay between consecutive timestamps
        delays = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
        return sum(delays) / len(delays) if delays else 0

    def _calculate_transition_patterns(self, tokens):
        """Calculate token transition patterns"""
        if not tokens or len(tokens) < 2:
            return {}
        
        categories = [t.get('category', 'general') for t in tokens]
        transitions = []
        
        for i in range(len(categories) - 1):
            transitions.append(f"{categories[i]}->{categories[i+1]}")
        
        from collections import Counter
        return dict(Counter(transitions))

    def extract_features_data_security(self):
        """Extract data-security features using EFAL-Pa approach"""
        print("\n" + "="*60)
        print("EXTRACTING DATA-SECURITY FEATURES (EFAL-Pa)")
        print("="*60)
        
        security_features = []
        
        for folder_name, df in self.sensitivity_classified.items():
            for idx, row in df.iterrows():
                sensitivity = row.get('sensitivity_level', 'low')
                
                features = {
                    'source': folder_name,
                    'sensitivity_level': sensitivity,
                    'data_type': self._determine_data_type(row),
                    'semantic_category': self._determine_semantic_category(folder_name),
                    'confidentiality_required': sensitivity in ['high', 'medium'],
                    'integrity_required': sensitivity == 'high',
                    'authentication_required': 'auth' in folder_name or 'security' in folder_name,
                    'encryption_applicable': sensitivity in ['high', 'medium'],
                    'signature_required': sensitivity == 'high'
                }
                security_features.append(features)
        
        print(f"✓ Extracted security features for {len(security_features)} data fragments")
        return security_features

    def _determine_data_type(self, row):
        """Determine data type from row"""
        # Check for numerical columns
        numerical_cols = ['score', 'grade', 'percentage', 'count', 'size', 'latency', 'rate']
        for col in row.index:
            col_lower = str(col).lower()
            if any(x in col_lower for x in numerical_cols):
                if isinstance(row[col], (int, float)):
                    return 'numerical'
        
        # Check for text columns
        text_cols = ['message', 'post', 'comment', 'feedback', 'description']
        for col in row.index:
            col_lower = str(col).lower()
            if any(x in col_lower for x in text_cols):
                if isinstance(row[col], str):
                    return 'text'
        
        return 'mixed'

    def _determine_semantic_category(self, folder_name):
        """Determine semantic category from folder name"""
        if any(x in folder_name for x in ['score', 'exam', 'grade', 'assignment']):
            return 'academic_assessment'
        elif any(x in folder_name for x in ['auth', 'security', 'token', 'encryption']):
            return 'security_control'
        elif any(x in folder_name for x in ['activity', 'log', 'event']):
            return 'system_activity'
        else:
            return 'general'

    def extract_features_api(self):
        """Extract API-privilege features using TuWaSa-API approach"""
        print("\n" + "="*60)
        print("EXTRACTING API-PRIVILEGE FEATURES (TuWaSa-API)")
        print("="*60)
        
        api_features = []
        
        if 'api_requests' in self.api_sequences:
            sequences = self.api_sequences['api_requests']
            
            # Group by user_id if available
            if sequences and 'user_id' in sequences[0]:
                user_groups = defaultdict(list)
                for item in sequences:
                    user_groups[item['user_id']].append(item)
                
                for user_id, user_sequences in user_groups.items():
                    for sequence in user_sequences:
                        features = {
                            'user_id': user_id,
                            'source_service': self._extract_source_service(sequence),
                            'destination_service': self._extract_destination_service(sequence),
                            'endpoint': sequence.get('endpoint'),
                            'permission_level': sequence.get('permission_level', 'low'),
                            'request_frequency': self._calculate_request_frequency(user_sequences),
                            'token_age': self._calculate_token_age(sequence),
                            'behavioral_entropy': self._calculate_behavioral_entropy(user_sequences),
                            'failed_attempts': self._calculate_failed_attempts(user_sequences),
                            'permission_overlap': self._calculate_permission_overlap(user_sequences)
                        }
                        api_features.append(features)
            else:
                # No user grouping
                for sequence in sequences:
                    features = {
                        'user_id': 'unknown',
                        'source_service': self._extract_source_service(sequence),
                        'destination_service': self._extract_destination_service(sequence),
                        'endpoint': sequence.get('endpoint'),
                        'permission_level': sequence.get('permission_level', 'low'),
                        'request_frequency': 0,
                        'token_age': 0,
                        'behavioral_entropy': 0,
                        'failed_attempts': self._calculate_failed_attempts([sequence]),
                        'permission_overlap': 0
                    }
                    api_features.append(features)
        
        print(f"✓ Extracted API features for {len(api_features)} requests")
        return api_features

    def _extract_source_service(self, sequence):
        """Extract source service from request"""
        return 'unknown'

    def _extract_destination_service(self, sequence):
        """Extract destination service from request"""
        endpoint = str(sequence.get('endpoint', ''))
        if '/api' in endpoint:
            return 'api_gateway'
        elif '/auth' in endpoint:
            return 'auth_service'
        else:
            return 'unknown'

    def _calculate_request_frequency(self, sequences):
        """Calculate request frequency for user"""
        if not sequences:
            return 0
        
        # Count requests per second based on timestamps
        timestamps = []
        for s in sequences:
            ts = s.get('timestamp')
            if ts:
                if hasattr(ts, 'timestamp'):
                    timestamps.append(ts.timestamp())
                elif isinstance(ts, (int, float)):
                    timestamps.append(float(ts))
        
        if len(timestamps) < 2:
            return 0
        
        time_range = max(timestamps) - min(timestamps)
        if time_range == 0:
            return 0
        
        return len(timestamps) / time_range

    def _calculate_token_age(self, sequence):
        """Calculate token age"""
        # If token_age_seconds exists in the data, use it
        if 'token_age_seconds' in sequence:
            return sequence.get('token_age_seconds', 0)
        
        # Otherwise try to calculate from timestamp
        ts = sequence.get('timestamp')
        if ts:
            if hasattr(ts, 'timestamp'):
                return datetime.now().timestamp() - ts.timestamp()
            elif isinstance(ts, (int, float)):
                return datetime.now().timestamp() - float(ts)
        
        return 0

    def _calculate_behavioral_entropy(self, sequences):
        """Calculate behavioral entropy"""
        if not sequences:
            return 0
        
        endpoints = [str(s.get('endpoint', 'unknown')) for s in sequences]
        from collections import Counter
        from math import log2
        
        counter = Counter(endpoints)
        total = len(endpoints)
        if total == 0:
            return 0
        
        probs = [count / total for count in counter.values() if count > 0]
        if not probs:
            return 0
        
        return -sum(p * log2(p) for p in probs)

    def _calculate_failed_attempts(self, sequences):
        """Calculate number of failed attempts"""
        if not sequences:
            return 0
        return sum(1 for s in sequences if s.get('status') in [401, 403])

    def _calculate_permission_overlap(self, sequences):
        """Calculate permission overlap"""
        if not sequences:
            return 0
        permissions = set(s.get('permission_level', 'low') for s in sequences)
        return len(permissions)

    def perform_full_preprocessing(self):
        """Execute all preprocessing operations"""
        print("="*60)
        print("STARTING FULL PREPROCESSING PIPELINE")
        print("="*60)
        
        # Load actual data
        self.load_all_data()
        
        if not self.data_snapshots:
            print("\n❌ ERROR: No data loaded. Please check your folder path.")
            print(f"   Base path: {self.base_path}")
            return {}
        
        # Process data
        self.capture_memory_snapshots()
        self.tokenize_memory()
        self.clean_and_normalize_data()
        self.classify_sensitivity()
        self.preprocess_api_requests()
        
        # Extract features
        memory_features = self.extract_features_memory()
        security_features = self.extract_features_data_security()
        api_features = self.extract_features_api()
        
        results = {
            'memory_features': memory_features,
            'security_features': security_features,
            'api_features': api_features,
            'tokenized_memory': self.tokenized_memory,
            'cleaned_data': self.cleaned_data,
            'sensitivity_data': self.sensitivity_classified,
            'api_sequences': self.api_sequences
        }
        
        print("\n" + "="*60)
        print("PREPROCESSING COMPLETE")
        print("="*60)
        print(f"✓ Memory features: {len(memory_features)}")
        print(f"✓ Security features: {len(security_features)}")
        print(f"✓ API features: {len(api_features)}")
        print("="*60)
        
        return results


class MemPViTFeatureExtractor:
    """Memory Snapshot Tokenized LightWeight Plain Vision Transformer"""
    
    def __init__(self, preprocessor_results):
        self.memory_features = preprocessor_results.get('memory_features', [])
        self.feature_vectors = []
    
    def extract_features(self):
        """Extract Mem-PViT features from memory snapshots"""
        print("\n" + "="*60)
        print("MEM-PViT FEATURE EXTRACTION")
        print("="*60)
        
        features_matrix = []
        feature_names = [
            'token_count', 'unique_tokens', 'duplication_rate', 
            'sensitive_token_ratio', 'temporal_delay'
        ]
        
        for snapshot in self.memory_features:
            feature_vector = [
                snapshot.get('token_count', 0),
                snapshot.get('unique_tokens', 0),
                snapshot.get('duplication_rate', 0),
                snapshot.get('sensitive_token_ratio', 0),
                snapshot.get('temporal_delay', 0)
            ]
            features_matrix.append(feature_vector)
        
        self.feature_vectors = features_matrix
        print(f"✓ Extracted {len(features_matrix)} feature vectors with {len(feature_names)} features")
        
        return features_matrix, feature_names


class EFALPaFeatureExtractor:
    """EFAL-Pa Feature Extraction"""
    
    def __init__(self, preprocessor_results):
        self.security_features = preprocessor_results.get('security_features', [])
    
    def extract_features(self):
        """Extract EFAL-Pa features for data security decisions"""
        print("\n" + "="*60)
        print("EFAL-Pa FEATURE EXTRACTION")
        print("="*60)
        
        feature_matrix = []
        feature_names = [
            'sensitivity_level', 'data_type', 'confidentiality_required',
            'integrity_required', 'authentication_required', 
            'encryption_applicable', 'signature_required'
        ]
        
        label_encoders = {}
        
        for feature in self.security_features:
            sensitivity = feature.get('sensitivity_level', 'low')
            data_type = feature.get('data_type', 'mixed')
            
            feature_vector = [
                self._encode_categorical(sensitivity, 'sensitivity', label_encoders),
                self._encode_categorical(data_type, 'data_type', label_encoders),
                int(feature.get('confidentiality_required', False)),
                int(feature.get('integrity_required', False)),
                int(feature.get('authentication_required', False)),
                int(feature.get('encryption_applicable', False)),
                int(feature.get('signature_required', False))
            ]
            feature_matrix.append(feature_vector)
        
        print(f"✓ Extracted {len(feature_matrix)} feature vectors")
        return feature_matrix, feature_names
    
    def _encode_categorical(self, value, field, encoders):
        """Encode categorical values"""
        if field not in encoders:
            encoders[field] = {}
        if value not in encoders[field]:
            encoders[field][value] = len(encoders[field])
        return encoders[field][value]


class TuWaSaAPIFeatureExtractor:
    """TuWaSa-API Feature Extraction"""
    
    def __init__(self, preprocessor_results):
        self.api_features = preprocessor_results.get('api_features', [])
    
    def extract_features(self):
        """Extract TuWaSa-API features for privilege analysis"""
        print("\n" + "="*60)
        print("TuWaSa-API FEATURE EXTRACTION")
        print("="*60)
        
        feature_matrix = []
        feature_names = [
            'permission_level', 'request_frequency', 'token_age',
            'behavioral_entropy', 'failed_attempts', 'permission_overlap'
        ]
        
        label_encoders = {}
        
        for feature in self.api_features:
            permission = feature.get('permission_level', 'low')
            
            feature_vector = [
                self._encode_categorical(permission, 'permission', label_encoders),
                feature.get('request_frequency', 0),
                feature.get('token_age', 0),
                feature.get('behavioral_entropy', 0),
                feature.get('failed_attempts', 0),
                feature.get('permission_overlap', 0)
            ]
            feature_matrix.append(feature_vector)
        
        print(f"✓ Extracted {len(feature_matrix)} feature vectors")
        return feature_matrix, feature_names
    
    def _encode_categorical(self, value, field, encoders):
        """Encode categorical values"""
        if field not in encoders:
            encoders[field] = {}
        if value not in encoders[field]:
            encoders[field][value] = len(encoders[field])
        return encoders[field][value]


class DetectionEngine:
    """Detection engine for identifying security threats"""
    
    def __init__(self, preprocessor_results):
        self.memory_features = preprocessor_results.get('memory_features', [])
        self.security_features = preprocessor_results.get('security_features', [])
        self.api_features = preprocessor_results.get('api_features', [])
        self.anomaly_threshold = 0.75
    
    def detect_memory_attacks(self):
        """Detect memory-based attacks"""
        print("\n" + "="*60)
        print("MEMORY ATTACK DETECTION")
        print("="*60)
        
        memory_threats = []
        
        for snapshot in self.memory_features:
            anomaly_score = 0
            indicators = []
            
            # Check for unusual duplication
            if snapshot.get('duplication_rate', 0) > 0.8:
                anomaly_score += 0.3
                indicators.append('high_duplication')
            
            # Check for high sensitive token ratio
            if snapshot.get('sensitive_token_ratio', 0) > 0.7:
                anomaly_score += 0.3
                indicators.append('high_sensitivity')
            
            # Check for unusual temporal delays
            if snapshot.get('temporal_delay', 0) > 3.0:
                anomaly_score += 0.2
                indicators.append('unusual_delay')
            
            # Check token count anomalies
            if snapshot.get('token_count', 0) > 100:
                anomaly_score += 0.2
                indicators.append('excessive_tokens')
            
            # Normalize score
            anomaly_score = min(1.0, anomaly_score)
            
            threat = {
                'source': snapshot.get('source', 'unknown'),
                'anomaly_score': anomaly_score,
                'is_suspicious': anomaly_score > self.anomaly_threshold,
                'indicators': indicators
            }
            memory_threats.append(threat)
        
        suspicious_count = sum(1 for t in memory_threats if t['is_suspicious'])
        print(f"✓ Detected {suspicious_count} suspicious memory events out of {len(memory_threats)}")
        return memory_threats
    
    def apply_efal_pa_security(self):
        """Apply EFAL-Pa security decisions"""
        print("\n" + "="*60)
        print("EFAL-Pa SECURITY ENFORCEMENT")
        print("="*60)
        
        security_decisions = []
        
        for feature in self.security_features:
            sensitivity = feature.get('sensitivity_level', 'low')
            data_type = feature.get('data_type', 'mixed')
            
            # Decision logic based on characteristics
            if sensitivity == 'high':
                if data_type == 'numerical':
                    security_operation = 'FALCON + Paillier'
                else:
                    security_operation = 'FALCON'
            elif sensitivity == 'medium':
                if data_type == 'numerical':
                    security_operation = 'Paillier'
                else:
                    security_operation = 'context_dependent'
            else:
                security_operation = 'lightweight'
            
            decision = {
                'source': feature.get('source', 'unknown'),
                'sensitivity': sensitivity,
                'data_type': data_type,
                'security_operation': security_operation,
                'encryption_applied': security_operation in ['Paillier', 'FALCON + Paillier'],
                'signature_applied': security_operation in ['FALCON', 'FALCON + Paillier']
            }
            security_decisions.append(decision)
        
        print(f"✓ Applied security decisions to {len(security_decisions)} data fragments")
        return security_decisions
    
    def detect_api_threats(self):
        """Detect API privilege escalation threats"""
        print("\n" + "="*60)
        print("API THREAT DETECTION (TuWaSa-API)")
        print("="*60)
        
        api_threats = []
        
        for feature in self.api_features:
            threat_score = 0
            threat_indicators = []
            
            # Check permission level
            permission = feature.get('permission_level', 'low')
            if permission in ['high', 'medium']:
                threat_score += 0.2
            
            # Check request frequency (potential DOS)
            if feature.get('request_frequency', 0) > 10:
                threat_score += 0.2
                threat_indicators.append('high_frequency')
            
            # Check token age (stale tokens)
            if feature.get('token_age', 0) > 1800:  # 30 minutes
                threat_score += 0.2
                threat_indicators.append('stale_token')
            
            # Check failed attempts (brute force)
            if feature.get('failed_attempts', 0) > 3:
                threat_score += 0.2
                threat_indicators.append('brute_force')
            
            # Check permission overlap (privilege escalation)
            if feature.get('permission_overlap', 0) > 2:
                threat_score += 0.2
                threat_indicators.append('permission_overlap')
            
            # Normalize score
            threat_score = min(1.0, threat_score)
            
            # Classify attack type
            attack_type = 'suspicious_behavior'
            if 'brute_force' in threat_indicators:
                attack_type = 'brute_force_attack'
            elif 'stale_token' in threat_indicators and 'high_frequency' in threat_indicators:
                attack_type = 'token_reuse_attack'
            elif 'permission_overlap' in threat_indicators:
                attack_type = 'privilege_escalation'
            elif 'high_frequency' in threat_indicators:
                attack_type = 'dos_attempt'
            
            threat = {
                'user_id': feature.get('user_id', 'unknown'),
                'threat_score': threat_score,
                'is_threat': threat_score > self.anomaly_threshold,
                'indicators': threat_indicators,
                'attack_type': attack_type
            }
            api_threats.append(threat)
        
        threat_count = sum(1 for t in api_threats if t['is_threat'])
        print(f"✓ Detected {threat_count} API threats out of {len(api_threats)}")
        return api_threats


# Main execution function
def run_preprocessing_pipeline(base_path):
    """Run the complete preprocessing pipeline"""
    
    # Initialize preprocessor
    preprocessor = ELearningSecurityPreprocessor(base_path)
    
    # Run preprocessing
    results = preprocessor.perform_full_preprocessing()
    
    if not results:
        print("\n❌ Pipeline failed. No data was processed.")
        return None
    
    # Initialize feature extractors
    print("\n" + "="*60)
    print("FEATURE EXTRACTION PHASE")
    print("="*60)
    
    # Mem-PViT feature extraction
    mem_extractor = MemPViTFeatureExtractor(results)
    mem_features, mem_feature_names = mem_extractor.extract_features()
    
    # EFAL-Pa feature extraction
    efal_extractor = EFALPaFeatureExtractor(results)
    security_features, security_feature_names = efal_extractor.extract_features()
    
    # TuWaSa-API feature extraction
    tuwasa_extractor = TuWaSaAPIFeatureExtractor(results)
    api_features, api_feature_names = tuwasa_extractor.extract_features()
    
    # Initialize detection engine
    print("\n" + "="*60)
    print("DETECTION PHASE")
    print("="*60)
    
    detector = DetectionEngine(results)
    
    # Run detection
    memory_threats = detector.detect_memory_attacks()
    security_decisions = detector.apply_efal_pa_security()
    api_threats = detector.detect_api_threats()
    
    # Compile final results
    final_results = {
        'preprocessing': results,
        'features': {
            'mem_pvit': {'features': mem_features, 'names': mem_feature_names},
            'efal_pa': {'features': security_features, 'names': security_feature_names},
            'tuwasa_api': {'features': api_features, 'names': api_feature_names}
        },
        'detection': {
            'memory_threats': memory_threats,
            'api_threats': api_threats,
            'security_decisions': security_decisions
        }
    }
    
    # Print summary
    print("\n" + "="*60)
    print("FINAL SUMMARY")
    print("="*60)
    print(f"✓ Total memory features extracted: {len(mem_features)}")
    print(f"✓ Total security features extracted: {len(security_features)}")
    print(f"✓ Total API features extracted: {len(api_features)}")
    print(f"✓ Memory threats detected: {sum(1 for t in memory_threats if t['is_suspicious'])}")
    print(f"✓ API threats detected: {sum(1 for t in api_threats if t['is_threat'])}")
    print(f"✓ Security decisions applied: {len(security_decisions)}")
    print("="*60)
    
    return final_results


# Example usage
if __name__ == "__main__":
    # Your path
    base_path = r".\Tri_ELM_Dataset"
    
    # Run the pipeline
    results = run_preprocessing_pipeline(base_path)
    
    if results:
        # Save results to JSON
        def convert_to_serializable(obj):
            if isinstance(obj, np.ndarray):
                return obj.tolist()
            elif isinstance(obj, datetime):
                return obj.isoformat()
            elif isinstance(obj, pd.Timestamp):
                return obj.isoformat()
            elif isinstance(obj, pd.DataFrame):
                return obj.to_dict('records')
            elif isinstance(obj, pd.Series):
                return obj.to_dict()
            else:
                return str(obj) if hasattr(obj, '__dict__') else obj
        
        with open('preprocessing_results.json', 'w') as f:
            json.dump(results, f, default=convert_to_serializable, indent=2)
        
        print("\n✅ Results saved to preprocessing_results.json")
        
        # Print sample of results
        print("\n" + "="*60)
        print("SAMPLE RESULTS")
        print("="*60)
        
        if results['preprocessing']['memory_features']:
            print(f"\nMemory Feature Sample:")
            print(json.dumps(results['preprocessing']['memory_features'][0], indent=2, default=str))
        
        if results['preprocessing']['api_features']:
            print(f"\nAPI Feature Sample:")
            print(json.dumps(results['preprocessing']['api_features'][0], indent=2, default=str))
        
        if results['detection']['security_decisions']:
            print(f"\nSecurity Decision Sample:")
            print(json.dumps(results['detection']['security_decisions'][0], indent=2))
    else:
        print("\n❌ No results to save.")